"""Alert-first incremental generations under complete frozen dependency closure.

Bootstrap may evaluate Full once. increment never calls AnalysisService._execute,
run_correlation or run_reconstruction. Scoring and controlled clustering remain
the existing implementations, with only their invalidated inputs replayed.
"""

from collections import Counter, defaultdict
import copy
import json
import time

from app.adapters.base import reject_truth
from app.chains.assembly import assemble_chain
from app.correlation.candidates import CandidateGenerator
from app.correlation.edges import correlation_version, peak_memory_mb
from app.correlation.index import AlertIndex
from app.correlation.scoring import CorrelationScorer
from app.dedup.grouping import DuplicateScorer, deduplicate
from app.entities.extraction import extract_entities
from app.incidents.clustering import cluster_incidents
from app.incidents.triage import triage_singletons
from app.models import CanonicalAlert, CorrelationEdge, DedupeGroup, Entity, Incident, AttackChain, AnalysisRecord
from app.services.incremental_dependencies import (adjacency, closure, decode_endpoint,
    duplicate_keys, encode_endpoint, schedule, json_value)
from app.services.incremental_store import IncrementalStore, TABLES
from app.services.storage import SnapshotStore, RunAnalysisRecord, run_identity
from app.utils.stable_id import canonical_json, content_digest, id_for


def payload_map(items, key):
    return {getattr(item, key): item.model_dump(mode='json') for item in items}


def pair_key(pair):
    return canonical_json(list(pair))


class IncrementalService:
    def __init__(self, workspace, config, source_settings, *, snapshot_root=None, progress=None, allowed_files=()):
        self.config, self.settings = config, source_settings
        self.snapshot = {'algorithm':config.snapshot,
            'sources':{k:v.snapshot() for k,v in sorted(source_settings.items())}}
        self.config_hash = content_digest(self.snapshot)
        self.store = IncrementalStore(workspace, self.config_hash)
        self.snapshot_root, self.progress = snapshot_root, progress
        from pathlib import Path
        self.allowed_files={Path(path).resolve() for path in allowed_files}
        self.tables = self.store.load()
        self.head = self.store.head()
        if self.head and snapshot_root is not None:
            self.store.publish(snapshot_root, self.head, self.tables)

    def close(self):
        self.store.close()

    def _notify(self, stage, **values):
        if self.progress:
            self.progress({'stage':stage, **values})

    def bootstrap_snapshot(self, root, analysis_id, *, fault=None):
        parent = SnapshotStore(root, analysis_id)
        record, _, _ = parent.read_metadata()
        if not record.is_complete or record.config_hash != self.config_hash:
            raise ValueError('incremental_parent_not_complete_or_config_mismatch')
        return self.bootstrap(list(parent.read_records('alerts')), parent_analysis_id=analysis_id, fault=fault)

    def bootstrap(self, alerts, *, parent_analysis_id=None, fault=None):
        if self.head:
            raise ValueError('incremental_workspace_already_initialized')
        return self._apply(alerts, bootstrap=True, parent_analysis_id=parent_analysis_id, fault=fault)

    def increment(self, alerts, *, fault=None):
        if not self.head:
            raise ValueError('incremental_workspace_not_initialized')
        return self._apply(alerts, bootstrap=False, fault=fault)

    def ingest(self, inputs, adapters, *, fault=None):
        """Normalize only the Delta through the already configured source adapters.

        Input paths and annotation isolation use the existing allowlist contract;
        callers supply source adapters, never derived fields or scoring overrides.
        """
        from pathlib import Path
        batches = []
        for source, path in inputs:
            original=Path(path).absolute()
            path = original.resolve()
            if 'evaluation' in {p.lower() for p in path.parts} or path.suffix.lower() not in {'.json','.jsonl','.ndjson'}:
                raise ValueError('incremental_input_not_security_alert')
            standard = (Path(self.snapshot_root)/'data/input/alerts').resolve() if self.snapshot_root else None
            if path not in self.allowed_files and (standard is None or not path.is_relative_to(standard)):
                raise ValueError('incremental_input_path_not_allowed')
            if path!=original or any(p.is_symlink() or hasattr(p,'is_junction') and p.is_junction() for p in (original,*original.parents)):
                raise ValueError('incremental_redirected_input')
            adapter=adapters[source]
            if adapter.config.config_hash!=self.config.config_hash or self.settings.get(adapter.settings.source_namespace)!=adapter.settings:
                raise ValueError('incremental_adapter_config_or_source_mismatch')
            batches.append(adapter.read_file(path))
        if any(batch.rejected for batch in batches):
            raise ValueError('incremental_rejected_input')
        return self.increment([alert for batch in batches for alert in batch.alerts], fault=fault)

    def records(self):
        return {'alerts':list(self.tables['canonical_identity'].values()),
            'dedupe_groups':list(self.tables['dedupe_groups'].values()),
            'entities':list(self.tables['domain_entities'].values()),
            'correlation_edges':list(self.tables['formal_edges'].values()),
            'incidents':list(self.tables['domain_incidents'].values()),
            'attack_chains':list(self.tables['domain_chains'].values()),
            'candidates':self.tables['candidate_state']}

    def _score(self, index, scorer, pair):
        winner = observed = None
        verified = 0
        for left in index.groups[pair[0]]:
            for right in index.groups[pair[1]]:
                scored = scorer.score_pair(left, right)
                verified += 1
                tie = (-scored.score, index.alerts[left].timestamp, index.alerts[right].timestamp, left, right)
                if observed is None or tie < observed[0]:
                    observed = (tie, scored)
                if scored.valid and (winner is None or tie < winner[0]):
                    winner = (tie, scored)
        selected = winner[1] if winner else None
        evaluated = selected if selected is not None else observed[1]
        accepted = selected is not None and selected.score >= scorer.algorithm.score.correlation_threshold
        edge = None
        if accepted:
            data = dict(source_alert_id=pair[0], target_alert_id=pair[1], score=round(selected.score,6),
                reasons=selected.reasons, entity_ids=selected.entity_ids, score_breakdown=scorer.breakdown(selected),
                support_pair={'alert_id_src':selected.source_member_id, 'alert_id_dst':selected.target_member_id})
            data['edge_id'] = id_for('CorrelationEdge', data)
            context = {'alerts':index.alerts, 'groups':index.groups, 'config_hash':self.config_hash,
                'score_weights':scorer.algorithm.score.weights.model_dump(),
                'independence_rule_ids':sorted({r.id for m in scorer.independence_mappings for r in m.rules})}
            edge = CorrelationEdge.model_validate(data, context=context)
        audit = evaluated.diagnostics.get('evidence_v2', {})
        return {'edge_id':edge.edge_id if edge else None,
            'unrounded_score':selected.score if selected else None,
            'support_pair':[selected.source_member_id, selected.target_member_id] if selected else None,
            'verified_member_pairs':verified, 'gate_passed':bool(audit.get('evidence_gate_passed',True)),
            'decision':audit.get('decision', 'ACCEPT' if accepted else 'REJECT'),
            'entity_dependencies':sorted(set().union(*(set(index.alerts[a].entity_ids)&set(index.alerts[b].entity_ids)
                for a in index.groups[pair[0]] for b in index.groups[pair[1]]))),
            'eligible':bool(accepted and selected.score >= scorer.algorithm.clustering.edge_threshold)}, edge

    def _apply(self, incoming, *, bootstrap, parent_analysis_id=None, fault=None):
        started = time.perf_counter()
        old = self.tables
        incoming = list(incoming)
        incoming_map = {}
        for value in incoming:
            alert = CanonicalAlert.model_validate(value.model_dump() if hasattr(value,'model_dump') else value)
            reject_truth(alert.raw_alert)
            if id_for('CanonicalAlert',alert) != alert.alert_id:
                raise ValueError('incremental_alert_identity_mismatch')
            # Entity facts are derived from base fields, never trusted from callers.
            base = alert.model_dump(mode='json')
            base.update(entity_ids=[], entity_occurrences=[], relations=[])
            base.pop('contexts', None)
            base.pop('extraction_version', None)
            if alert.alert_id in incoming_map and incoming_map[alert.alert_id] != base:
                raise ValueError('incremental_same_id_conflict')
            incoming_map[alert.alert_id] = base
        batch_hash = content_digest([[k,v['raw_fingerprint']] for k,v in sorted(incoming_map.items())])
        new = {}
        for aid, value in sorted(incoming_map.items()):
            if aid in old['canonical_identity']:
                prior = dict(old['canonical_identity'][aid])
                prior.update(entity_ids=[], entity_occurrences=[], relations=[])
                prior.pop('contexts', None)
                prior.pop('extraction_version', None)
                if prior != value:
                    raise ValueError('incremental_same_id_conflict')
            else:
                new[aid] = CanonicalAlert.model_validate(value)
        receipt = self.store.committed_batch(batch_hash)
        if not bootstrap and receipt:
            return {**receipt, 'idempotent_replay':True}
        if not new:
            if bootstrap:
                raise ValueError('empty_incremental_bootstrap')
            return {**(self.head or {}), 'idempotent_replay':True, 'empty_or_duplicate_batch':True,
                'stats':{'incoming_alerts':len(incoming), 'new_canonical_alerts':0,
                    'duplicate_observations':len(incoming), 'candidate_pairs_scored':0,
                    'candidate_proposals_replayed':0, 'incident_components_replayed':0}}
        tables = {k:dict(v) for k,v in old.items()}
        timings={}
        stage_started=time.perf_counter()
        alerts = {k:CanonicalAlert.model_validate(v) for k,v in old['canonical_identity'].items()}
        alerts.update(new)
        groups = [DedupeGroup.model_validate(v) for v in old['dedupe_groups'].values()]
        ds = DuplicateScorer(alerts.values(), self.config, self.settings)
        key_buckets = {k:set(v) for k,v in old['duplicate_keys'].items()}
        duplicate_pairs = set()
        for aid in sorted(new):
            for key, window in duplicate_keys(ds, aid):
                for other in sorted(key_buckets.get(key,())):
                    if window is None or abs((ds.metadata[aid]['time']-ds.metadata[other]['time']).total_seconds()) <= window:
                        duplicate_pairs.add(tuple(sorted((aid,other))))
                key_buckets.setdefault(key,set()).add(aid)
        dup_adj = {k:set(v) for k,v in old['duplicate_adjacency'].items()}
        for a,b in duplicate_pairs:
            dup_adj.setdefault(a,set()).add(b)
            dup_adj.setdefault(b,set()).add(a)
        # Old group members stay in the complete component even when a newly
        # earlier-ranked candidate changes its complete-link partition.
        for group in groups:
            for aid in group.alert_ids:
                dup_adj.setdefault(aid,set()).update(set(group.alert_ids)-{aid})
        duplicate_scope = closure(new, dup_adj)
        replay = deduplicate([alerts[k] for k in sorted(duplicate_scope)],self.config,self.settings)
        if not replay.is_complete:
            raise MemoryError('incremental_dedupe_incomplete')
        groups = [g for g in groups if not set(g.alert_ids)&duplicate_scope] + replay.groups
        if bootstrap:
            # Build the rejected as well as accepted duplicate candidate graph.
            pairs, _ = ds.candidates()
            dup_adj = adjacency(pairs)
        timings['dedupe_seconds']=time.perf_counter()-stage_started
        stage_started=time.perf_counter()
        extracted = extract_entities(new.values(),self.settings)
        alerts.update({a.alert_id:a for a in extracted.alerts})
        entities = {k:Entity.model_validate(v) for k,v in old['domain_entities'].items()}
        for entity in extracted.entities:
            if entity.entity_id in entities:
                prior = entities[entity.entity_id]
                row = prior.model_dump()
                row['alert_ids'] = sorted(set(prior.alert_ids)|set(entity.alert_ids))
                if min(entity.alert_ids) < min(prior.alert_ids):
                    row['display_value'] = entity.display_value
                entities[entity.entity_id] = Entity.model_validate(row)
            else:
                entities[entity.entity_id] = entity
        index = AlertIndex(alerts.values(),groups,entities.values())
        scorer = CorrelationScorer(index,self.config,self.settings,self.config_hash)
        generator = CandidateGenerator(index,self.config,scorer)
        timings['entity_index_seconds']=time.perf_counter()-stage_started
        stage_started=time.perf_counter()
        old_N = old['analysis_frequency_state'].get('frequency',{}).get('N',0)
        old_df = {k:v['df'] for k,v in old['entity_df'].items()}
        changed_df = {k for k in set(old_df)|set(index.df) if old_df.get(k,0)!=index.df.get(k,0)}
        hot_changes, rarity_changes = set(),set()
        frequency = {}
        for eid, df in sorted(index.df.items()):
            hot = df >= generator.c.hot_entity_min_count and df/index.N >= generator.c.hot_entity_ratio
            rarity = index.rarity(eid,scorer.algorithm.entity)
            prior = old['entity_df'].get(eid)
            if prior and hot != prior['hot']:
                hot_changes.add(eid)
            if prior and rarity != prior['rarity']:
                rarity_changes.add(eid)
            frequency[eid] = {'df':df, 'hot':hot, 'rarity':rarity}
        old_owner = old['representative_owner']
        changed_groups = {rep for rep,members in index.groups.items() if
            any(old_owner.get(aid)!=rep for aid in members) or
            list(members)!=old['analysis_frequency_state'].get('groups',{}).get(rep)}
        reasons = defaultdict(set)
        for rep in changed_groups:
            reasons[rep].add('DIRECT:dedupe_or_delta_membership')
        direct = set(changed_groups)
        # Reverse lookup by exact scoped entity/semantic key and configured
        # maximum windows. No time-only pair ever becomes a nomination.
        for rep in changed_groups:
            for aid in index.groups[rep]:
                member = index.alerts[aid]
                keys = set(member.entity_ids)|set(generator.semantic_members.get(aid,()))|index.contexts_by_alert[aid]
                for eid in keys:
                    postings = generator.semantic.get(eid) or index.by_entity.get(eid) or index.by_context.get(eid,{})
                    for posting in postings.values():
                        window = generator.c.max_window_seconds*1000000
                        lo,hi = posting.bounds(index.times[aid]-window,index.times[aid]+window)
                        direct.update(index.owner[i] for i in posting.members[lo:hi])
        for rep in direct-changed_groups:
            reasons[rep].add('DIRECT:index_neighbor')
        endpoints = {k:decode_endpoint(v) for k,v in old['endpoint_proposals'].items() if k in index.groups}
        changed_members=[aid for rep in changed_groups for aid in index.groups[rep]]
        retired=set(old['endpoint_proposals'])-set(index.groups)
        def can_displace(rep):
            state=endpoints.get(rep)
            if state is None or not state['lookup_boundaries']:
                return True
            if retired.intersection(state['proposals']) or retired.intersection(state['discoveries']):
                return True
            for boundary in state['lookup_boundaries']:
                aid=boundary['member']
                if aid not in index.alerts:
                    return True
                channel,eid=boundary['channel'],boundary['entity_id']
                for other in changed_members:
                    if index.owner[other]==rep:
                        continue
                    keys=set(index.alerts[other].entity_ids)|set(generator.semantic_members.get(other,()))|index.contexts_by_alert[other]
                    if eid not in keys:
                        continue
                    before=index.times[other]-index.times[aid]
                    windows=generator.windows(channel,index.alerts[aid].category.value,index.alerts[other].category.value)
                    applicable=[window for side,window,_ in windows if side=='both' or
                        side=='before' and before<0 or side=='after' and before>0 or before==0]
                    if not applicable or abs(before)>max(applicable)*1000000:
                        continue
                    rank=(abs(before)/1000000,index.owner[other],aid,other)
                    worst=tuple(boundary['worst_rank']) if boundary['worst_rank'] else None
                    if boundary['retained']<boundary['limit'] or worst is None or rank<=worst:
                        return True
            return False
        lookup_scope = set(changed_groups)|{rep for rep in direct-changed_groups if can_displace(rep)}
        entity_users = defaultdict(set)
        for aid,member in index.alerts.items():
            for eid in set(member.entity_ids)|set(generator.semantic_members.get(aid,()))|index.contexts_by_alert[aid]:
                entity_users[eid].add(index.owner[aid])
        for eid in hot_changes:
            for rep in entity_users[eid]:
                lookup_scope.add(rep)
                reasons[rep].add('DEPENDENCY:hot_transition')
        # Missing endpoints (bootstrap/new representatives) must run official lookup.
        lookup_scope.update(set(index.groups)-endpoints.keys())
        self._notify('endpoint_replay', count=len(lookup_scope), N=index.N)
        endpoints.update(generator.generate(representatives=lookup_scope,endpoint_only=True))
        for eid in rarity_changes|changed_df:
            for rep in entity_users[eid]-lookup_scope:
                # Maintain changed stored scheduling priority without reretrieving.
                if endpoints[rep]['proposals']:
                    reasons[rep].add('DEPENDENCY:rarity_priority')
        candidates, priorities, cutoff, truncated = schedule(endpoints,generator)
        timings['candidate_seconds']=time.perf_counter()-stage_started
        old_candidates = old['candidate_state']
        pair_states, edges = {}, {k:CorrelationEdge.model_validate(v) for k,v in old['formal_edges'].items()}
        to_score = set()
        pair_reasons = defaultdict(set)
        candidate_added, candidate_removed, candidate_updated = [],[],[]
        for pair,candidate in sorted(candidates.items()):
            key = pair_key(pair)
            prior = old_candidates.get(key)
            evidence = [e.json_data() for e in candidate.evidence]
            signature = content_digest(json_value({'priority':candidate.priority,'evidence':evidence,'channels':candidate.channels}))
            if prior is None:
                to_score.add(pair)
                candidate_added.append(pair)
                pair_reasons[pair].add('DIRECT:new_candidate' if set(pair)&direct else 'DEPENDENCY:candidate_admission_or_budget')
            else:
                if prior['candidate_signature'] != signature:
                    candidate_updated.append(pair)
                    pair_reasons[pair].add('DEPENDENCY:candidate_rank_or_provenance')
                dependencies = set(prior['entity_dependencies'])
                # N is material when the frozen evidence includes population,
                # even with a floor/capped score; never freeze baseline frequency.
                population_change = old_N!=index.N and bool(dependencies) and self.config.algorithm.version in {'v3', 'v4'}
                if set(pair)&changed_groups or dependencies&(changed_df|hot_changes|rarity_changes) or population_change:
                    to_score.add(pair)
                    pair_reasons[pair].add('DIRECT:member_mutation' if set(pair)&changed_groups else 'DEPENDENCY:score_frequency')
            state = dict(prior) if prior else {}
            state.update(candidate_signature=signature, priority=list(candidate.priority), channels=list(candidate.channels),
                evidence=evidence)
            pair_states[key] = state
        for key,prior in old_candidates.items():
            pair = tuple(json.loads(key))
            if pair not in candidates:
                candidate_removed.append(pair)
                pair_reasons[pair].add('DIRECT:representative_retired' if set(pair)&retired
                    else 'DEPENDENCY:candidate_admission_or_budget_removal')
                if prior['edge_id']:
                    edges.pop(prior['edge_id'],None)
        self._notify('scoring', count=len(to_score), historical=sum(not set(p)&changed_groups for p in to_score))
        stage_started=time.perf_counter()
        for number,pair in enumerate(sorted(to_score),1):
            state,edge = self._score(index,scorer,pair)
            key = pair_key(pair)
            if pair_states[key].get('edge_id'):
                edges.pop(pair_states[key]['edge_id'],None)
            pair_states[key].update(state)
            if edge:
                edges[edge.edge_id] = edge
            for rep in pair:
                reasons[rep].update(pair_reasons[pair])
            if number%10000==0:
                self._notify('scoring_progress',done=number,total=len(to_score))
        timings['scoring_seconds']=time.perf_counter()-stage_started
        stage_started=time.perf_counter()
        for pair in candidate_removed+candidate_updated+candidate_added:
            for rep in pair:
                if rep in index.groups:
                    reasons[rep].add('DEPENDENCY:candidate_state')
        # Recover exact formal-edge eligibility from persisted unrounded outcomes.
        old_eligible = [tuple(json.loads(k)) for k,v in old_candidates.items() if v['eligible']]
        new_eligible = [tuple(json.loads(k)) for k,v in pair_states.items() if v['eligible']]
        remap = {rep:index.owner.get(rep,rep) for rep in old_owner.values()}
        graph = adjacency([(remap.get(a,a),remap.get(b,b)) for a,b in old_eligible]+new_eligible)
        graph_seeds = set(changed_groups)
        changed_edges = set()
        edge_payloads = payload_map(edges.values(),'edge_id')
        for key in set(old['formal_edges'])|set(edge_payloads):
            if old['formal_edges'].get(key)!=edge_payloads.get(key):
                changed_edges.add(key)
                row = edge_payloads.get(key) or old['formal_edges'][key]
                graph_seeds.update([remap.get(row['source_alert_id'],row['source_alert_id']),
                    remap.get(row['target_alert_id'],row['target_alert_id'])])
        # Scores can cross clustering/order boundaries below 6-decimal storage.
        for key in set(old_candidates)&set(pair_states):
            before,after = old_candidates[key],pair_states[key]
            if before['eligible']!=after['eligible'] or (after['eligible'] and before['unrounded_score']!=after['unrounded_score']):
                graph_seeds.update(json.loads(key))
        old_incidents = {k:Incident.model_validate(v) for k,v in old['domain_incidents'].items()}
        # Old Incident membership explicitly joins the split replay closure.
        for incident in old_incidents.values():
            reps = {index.owner[a] for a in incident.alert_ids}
            for rep in reps:
                graph.setdefault(rep,set()).update(reps-{rep})
        replay_reps = closure(graph_seeds,graph)&set(index.groups)
        for rep in replay_reps-graph_seeds:
            reasons[rep].add('DEPENDENCY:eligible_component_closure')
        graph_components, unseen = [],set(replay_reps)
        while unseen:
            component = closure({min(unseen)},graph)&set(index.groups)
            unseen.difference_update(component)
            graph_components.append(component)
        incidents = {k:v for k,v in old_incidents.items() if not
            {index.owner.get(a,old_owner.get(a)) for a in v.alert_ids}&replay_reps}
        cache, edge_map = {},edges
        for component in graph_components:
            local = copy.copy(index)
            local.representatives = tuple(sorted(component))
            # Keep original global N/df for scorer. The local clustering view
            # contains all members of precisely the old/new eligible component.
            local.groups = {k:index.groups[k] for k in sorted(component)}
            local_edges = [e for e in edges.values() if e.source_alert_id in component and e.target_alert_id in component]
            clustered = cluster_incidents(local,local_edges,scorer)
            incidents.update({i.incident_id:i for i in clustered.incidents})
            cache.update(clustered.support_cache)
        timings['clustering_seconds']=time.perf_counter()-stage_started
        stage_started=time.perf_counter()
        diag = {rep:{'candidate_count':0,'gate_passed_count':0,'formal_edge_count':0,'decisions':Counter()}
            for rep in index.representatives}
        for key,state in pair_states.items():
            for rep in json.loads(key):
                d = diag[rep]
                d['candidate_count']+=1
                d['gate_passed_count']+=int(state['gate_passed'])
                d['formal_edge_count']+=int(state['edge_id'] is not None)
                d['decisions'][state['decision']]+=1
        diag = {rep:{**d,'decisions':dict(d['decisions'])} for rep,d in diag.items()}
        rule_groups = defaultdict(set)
        for aid,a in index.alerts.items():
            if a.rule_id is not None:
                rule_groups[(a.source_namespace,a.rule_id)].add(index.owner[aid])
        rule_counts = {k:len(v) for k,v in rule_groups.items()}
        triage_scope = set()
        for key,incident in incidents.items():
            if len(incident.alert_ids)!=1:
                continue
            aid = incident.alert_ids[0]
            a,rep = index.alerts[aid],index.owner[aid]
            previous = old_incidents.get(key)
            rarity_available = (self.config.algorithm.single_alert_triage is not None
                and a.rule_id is not None and 'rule_id' in a.field_provenance)
            n_dependency = rarity_available and old_N!=index.N
            rule_changed = rarity_available and old['triage_rule_counts'].get(pair_key((a.source_namespace,a.rule_id)))!=rule_counts.get((a.source_namespace,a.rule_id))
            diagnostic_changed = old['triage_dependencies'].get(aid,{}).get('diagnostic')!=diag[rep]
            completeness_changed = bool(self.head and self.head['record']['candidate_truncated'])!=bool(truncated)
            if previous is None or n_dependency or rule_changed or diagnostic_changed or completeness_changed or rep in changed_groups:
                triage_scope.add(key)
                reasons[rep].add('DEPENDENCY:triage_population_or_rule_frequency' if previous else
                    'DIRECT:new_singleton' if aid in new else 'DEPENDENCY:triage_incident_membership')
        triaged = triage_singletons([incidents[k] for k in sorted(triage_scope)],index,self.config,
            {'alert_correlation_diagnostics':diag},search_complete=not bool(truncated),rule_counts=rule_counts)
        incidents.update({i.incident_id:i for i in triaged})
        timings['triage_seconds']=time.perf_counter()-stage_started
        stage_started=time.perf_counter()
        chains = {k:AttackChain.model_validate(v) for k,v in old['domain_chains'].items()
            if v['incident_id'] in incidents and not set(v['nodes'][0]['alert_ids'])&set(new)}
        chain_by_incident = {c.incident_id:c for c in chains.values()}
        for incident in incidents.values():
            if incident.incident_id not in chain_by_incident or {index.owner[a] for a in incident.alert_ids}&replay_reps:
                old_chain = chain_by_incident.get(incident.incident_id)
                if old_chain:
                    chains.pop(old_chain.chain_id,None)
                chain = assemble_chain(incident,index,scorer,[edge_map[k] for k in incident.correlation_edge_ids],support_cache=cache)
                chains[chain.chain_id]=chain
        timings['chain_seconds']=time.perf_counter()-stage_started
        tables['canonical_identity']=payload_map(index.alerts.values(),'alert_id')
        tables['domain_entities']=payload_map(index.entities.values(),'entity_id')
        tables['dedupe_groups']=payload_map(groups,'group_id')
        tables['representative_owner']=dict(index.owner)
        tables['duplicate_keys']={k:sorted(v) for k,v in key_buckets.items()}
        tables['duplicate_adjacency']={k:sorted(v) for k,v in dup_adj.items()}
        tables['observation_identity']={k:v.observation_id for k,v in ds.observation.identities.items()} if ds.observation else {}
        tables['entity_postings']={k:sorted(v) for k,v in entity_users.items()}
        tables['entity_df']=frequency
        tables['time_postings']={aid:[index.times[aid],index.owner[aid],a.category.value] for aid,a in index.alerts.items()}
        tables['source_postings']={aid:[a.source_namespace,a.source_type.value,a.sensor] for aid,a in index.alerts.items()}
        tables['semantic_postings']={k:sorted(v) for k,v in generator.semantic_members.items()}
        tables['endpoint_proposals']={k:encode_endpoint(v) for k,v in endpoints.items()}
        reverse_candidates=defaultdict(list)
        for key,state in pair_states.items():
            for eid in state['entity_dependencies']:
                reverse_candidates[eid].append(key)
        tables['candidate_dependencies']={k:sorted(v) for k,v in reverse_candidates.items()}
        tables['candidate_priority']=priorities
        tables['candidate_state']=pair_states
        tables['formal_edges']=edge_payloads
        tables['edge_support']={e.edge_id:[e.support_pair.alert_id_src,e.support_pair.alert_id_dst] for e in edges.values()}
        tables['domain_incidents']=payload_map(incidents.values(),'incident_id')
        tables['domain_chains']=payload_map(chains.values(),'chain_id')
        tables['incident_membership']={aid:i.incident_id for i in incidents.values() for aid in i.alert_ids}
        tables['eligible_edge_adjacency']={k:sorted(v) for k,v in adjacency(new_eligible).items()}
        tables['triage_rule_counts']={pair_key(k):v for k,v in rule_counts.items()}
        tables['triage_dependencies']={i.alert_ids[0]:{'rule':[index.alerts[i.alert_ids[0]].source_namespace,
            index.alerts[i.alert_ids[0]].rule_id], 'N_dependency':bool(index.alerts[i.alert_ids[0]].rule_id),
            'diagnostic':diag[index.owner[i.alert_ids[0]]]} for i in incidents.values() if len(i.alert_ids)==1}
        tables['analysis_frequency_state']={'frequency':index.frequency_snapshot(),
            'groups':{k:list(v) for k,v in index.groups.items()},'candidate_cutoff':cutoff}
        old_incident_payloads=old['domain_incidents']
        new_incident_payloads=tables['domain_incidents']
        historical_changed_incidents = sum(not set(v['alert_ids'])&set(new) and old_incident_payloads.get(k)!=v
            for k,v in new_incident_payloads.items())
        incident_overlaps = {k:{tables['incident_membership'][a] for a in v['alert_ids']} for k,v in old_incident_payloads.items()}
        reverse_overlaps=defaultdict(set)
        for k,targets in incident_overlaps.items():
            for target in targets:
                reverse_overlaps[target].add(k)
        affected=set(reasons)|replay_reps
        historical=lambda pairs:sum(not set(p)&changed_groups for p in pairs)
        stats=dict(incoming_alerts=len(incoming),new_canonical_alerts=len(new),duplicate_observations=len(incoming)-len(new)+
            len(new)-max(0,index.N-old_N),
            old_N=old_N,new_N=index.N,changed_entity_df_count=len(changed_df),hot_state_transition_count=len(hot_changes),
            rarity_dependency_changes=len(rarity_changes),affected_representatives=len(affected),
            direct_delta_neighbors=len(direct),dependency_only_affected_representatives=len(affected-direct),
            candidate_proposals_replayed=len(lookup_scope),historical_candidates_added=historical(candidate_added),
            historical_candidates_removed=historical(candidate_removed),historical_candidates_updated=historical(candidate_updated),
            candidate_pairs_scored=len(to_score),historical_pairs_rescored=historical(to_score),
            edges_inserted=len(edge_payloads.keys()-old['formal_edges'].keys()),
            edges_updated=sum(old['formal_edges'][k]!=edge_payloads[k] for k in old['formal_edges'].keys()&edge_payloads.keys()),
            edges_deleted=len(old['formal_edges'].keys()-edge_payloads.keys()),incident_components_replayed=len(graph_components),
            incident_representatives_replayed=len(replay_reps),incidents_created=len(new_incident_payloads.keys()-old_incident_payloads.keys()),
            incidents_updated=sum(old_incident_payloads[k]!=new_incident_payloads[k] for k in old_incident_payloads.keys()&new_incident_payloads.keys()),
            incidents_merged=sum(len(v)>1 for v in reverse_overlaps.values()),incidents_split=sum(len(v)>1 for v in incident_overlaps.values()),
            triage_records_updated=len(triage_scope),dependency_closure_ratio=len(affected)/index.N,
            historical_incidents_changed_without_delta_membership=historical_changed_incidents,
            full_candidate_count=len(candidates),full_incident_count=len(incidents),duplicate_component_alerts_replayed=len(duplicate_scope),
            total_time=time.perf_counter()-started,peak_memory=peak_memory_mb(),broad_dependency_closure=len(affected)==index.N,
            broad_dependency_reasons=sorted({r.split(':',1)[1] for rep in affected-direct for r in reasons[rep]}))
        stats['stage_runtime']=timings
        record_data=dict(input_alert_ids=list(index.alerts),config_hash=self.config_hash,config_digest=self.config_hash,
            config_snapshot=self.snapshot,algorithm_version=correlation_version(self.config),mapping_digest=self.config.mapping_digest,
            dataset_digest=content_digest([[k,a.raw_fingerprint] for k,a in index.alerts.items()]),
            is_complete=not bool(truncated),status='incomplete' if truncated else 'completed',candidate_truncated=bool(truncated),
            incomplete_reason='candidate_resource_truncation' if truncated else None,errors=['candidate_resource_truncation'] if truncated else [],
            metrics=dict(alert_count=len(index.alerts),representative_count=index.N,candidate_pair_count=len(candidates),
                candidate_dropped_count=truncated,correlation_runtime_seconds=timings['candidate_seconds']+timings['scoring_seconds'],
                clustering_runtime_seconds=timings['clustering_seconds'],chain_runtime_seconds=timings['chain_seconds'],
                total_runtime_seconds=stats['total_time'],peak_memory_mb=stats['peak_memory']))
        identity=id_for('AnalysisRecord',record_data)
        record_data.update(analysis_id=identity,diagnostics_ref=f'outputs/analyses/{identity}/diagnostics.jsonl',
            frequency_snapshot_ref=f'outputs/analyses/{identity}/frequency_snapshot.json')
        record=AnalysisRecord.model_validate(record_data)
        parent=parent_analysis_id or (self.head['analysis_id'] if self.head else None)
        generation_id=content_digest({'parent':parent,'batch_hash':batch_hash,'config_hash':self.config_hash,
            'algorithm_version':record.algorithm_version,'snapshot':identity})
        audit=[{'stage':'incremental_affected_representative','representative':rep,'reasons':sorted(reasons[rep])}
            for rep in sorted(affected)]
        audit += [{'stage':'incremental_pair','support_key':list(pair),'reasons':sorted(pair_reasons[pair]),
            'rescored':pair in to_score} for pair in sorted(pair_reasons)]
        audit += [{'stage':'incremental_edge','edge_id':key,
            'reasons':['DEPENDENCY:member_score_or_candidate_state']} for key in sorted(changed_edges)]
        audit += [{'stage':'incremental_incident_component','representatives':sorted(component),
            'reasons':['DEPENDENCY:eligible_edge_or_historical_membership_closure']}
            for component in graph_components]
        logical_identity=identity
        identity=run_identity(generation_id)
        record_data.update(analysis_id=identity,diagnostics_ref=f'outputs/analyses/{identity}/diagnostics.jsonl',
            frequency_snapshot_ref=f'outputs/analyses/{identity}/frequency_snapshot.json')
        record=RunAnalysisRecord.model_validate(record_data)
        generation={'generation_id':generation_id,'analysis_id':identity,'parent_analysis_id':parent,'batch_hash':batch_hash,
            'config_hash':self.config_hash,'algorithm_version':record.algorithm_version,'record':record.model_dump(mode='json'),
            'frequency':index.frequency_snapshot(),'stats':stats,'audit':audit,'bootstrap':bootstrap,
            'candidate_contract_version':'v1.1','ground_truth_used':False,
            'execution':{'token':generation_id,'snapshot_identity':logical_identity}}
        try:
            self.store.commit(tables,generation,fault,expected_head=self.head['generation_id'] if self.head else None)
        except BaseException:
            # COMMIT can succeed before a caller/process fault. Refresh the
            # committed head so this instance cannot reuse stale precommit facts.
            self.tables,self.head=self.store.load(),self.store.head()
            raise
        self.tables,self.head=tables,generation
        if self.snapshot_root is not None:
            self.store.publish(self.snapshot_root,generation,tables,fault)
        self._notify('committed',analysis_id=identity,stats=stats)
        return generation
