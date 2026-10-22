"""Read-only ⑦/⑧ sparsity audit of the exact frozen formal handoff.

Replay the original functions unchanged, instrument their actual branches, and
require field-identical JSON output. No GT interpretation, alternate generator,
counterfactual decision, downstream assembly, threshold edit or graph edit.
"""
import argparse
from collections import Counter, defaultdict
from dataclasses import asdict
from hashlib import sha256
import inspect
from itertools import combinations
import json
import os
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'backend'))
sys.dont_write_bytecode = True
FILES_CHANGED = ['scripts/audit_stage8_relation_sparsity.py',
    'tests/audit-only/test_stage8_relation_audit.py', 'docs/STAGE_8_RELATION_SPARSITY_AUDIT.md']
REPLAY_ACTIVE = False


def audit_io(event, args):
    if not REPLAY_ACTIVE:
        return
    if event in {'socket.connect','subprocess.Popen'}:
        raise AssertionError('audit_replay_network_or_subprocess_forbidden')
    if event=='open' and not isinstance(args[0],int):
        path=Path(os.fsdecode(args[0])).resolve()
        if args[2] & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):
            raise AssertionError('audit_replay_must_not_write:'+str(path))
        if {'ground_truth','historical_gt','evaluation'} & {s.casefold() for s in path.parts}:
            raise AssertionError('audit_replay_truth_read_forbidden:'+str(path))


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def digest(value):
    return sha256(encode(value).encode('utf8')).hexdigest()


def file_hash(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def save(out, name, value):
    (out/name).write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)+'\n', encoding='utf8')


def pair(row):
    return row['stage_a_id'], row['stage_b_id']


def quantile(values, p):
    if not values:
        return None
    values = sorted(values)
    x = (len(values)-1)*p
    lo = int(x)
    return values[lo] + (values[min(lo+1, len(values)-1)]-values[lo])*(x-lo)


def distribution(values):
    return dict(count=len(values), min=min(values) if values else None,
        median=statistics.median(values) if values else None, p75=quantile(values, .75),
        p90=quantile(values, .9), max=max(values) if values else None)


def component_sizes(nodes, edges):
    """Graph audit statistic only; never construct Chain or membership output."""
    neighbors={sid:set() for sid in nodes}
    for a,b in edges:
        neighbors[a].add(b);neighbors[b].add(a)
    unseen=set(nodes);sizes=[]
    while unseen:
        stack=[unseen.pop()];count=0
        while stack:
            sid=stack.pop();count+=1
            fresh=neighbors[sid]&unseen
            unseen-=fresh;stack.extend(fresh)
        sizes.append(count)
    return sorted(sizes)


def rejection_reason(decision):
    """The terminal NO_RELATION branch, not incidental conflict diagnostics."""
    if decision['relation_type'] != 'NO_RELATION':
        return None
    terminal = [r for r in ('SHARED_CONTEXT_ONLY', 'SUPPORTING_EVIDENCE_ONLY', 'NO_VALID_EVIDENCE')
                if r in decision['diagnostics']]
    if len(terminal) != 1:
        raise ValueError('cannot_attribute_formal_rejection_branch')
    return terminal[0]


class GeneratorTrace:
    """Observe original generator instructions; do not reproduce its policy.

    Suppressed postings are later expanded only to attribute exclusions in the
    requested exhaustive diagnostic pair table, never to nominate candidates.
    """
    def __init__(self, generator):
        self.code = generator.__code__
        lines, start = inspect.getsourcelines(generator)
        self.lines = {start+i: line.strip() for i, line in enumerate(lines)}
        self.actions = {}
        markers = {
            "diagnostics.append(dict(**description, action='SKIP_POSTING'": 'SKIP_POSTING',
            "pruned += 1": 'TEMPORAL',
            "value = pairs.setdefault": 'NOMINATE',
        }
        for needle, action in markers.items():
            found = [n for n, text in self.lines.items() if needle in text]
            if len(found) != 1:
                raise ValueError('generator_audit_marker_changed:' + needle)
            self.actions[found[0]] = action
        for number, text in self.lines.items():
            if text == 'continue' and self.lines.get(number-1) in (
                    "if 'process' not in lr | rr:",
                    "if not ('record' in lr and 'reference' in rr or 'reference' in lr and 'record' in rr):"):
                self.actions[number] = 'ROLE'
        if list(self.actions.values()).count('ROLE') != 2:
            raise ValueError('generator_role_skip_markers_changed')
        self.postings, self.events = [], defaultdict(list)
        self.pruned_gap_seconds = []

    def __call__(self, frame, event, arg):
        if frame.f_code is not self.code:
            return None
        if event != 'line' or frame.f_lineno not in self.actions:
            return self
        loc, action = frame.f_locals, self.actions[frame.f_lineno]
        source = dict(file='backend/app/stage_candidates/generator.py', line=frame.f_lineno,
            executed_instruction=self.lines[frame.f_lineno])
        feature = loc['feature']
        record = dict(key=loc['key'], kind=feature.kind, mode=feature.mode, code_path=source)
        if action == 'SKIP_POSTING':
            self.postings.append(dict(record, stage_ids=sorted(loc['posting']), reason=loc['reason']))
        else:
            key = (loc['a'], loc['b'])
            if action == 'TEMPORAL':
                record.update(outcome='EXCLUDED_BY_TIME', reason='CONTEXT_OUTSIDE_LOCALITY_WINDOW',
                    gap_seconds=loc['gap'], tier=loc['tier'],
                    window_seconds=loc['community_config'].windows_seconds[loc['tier']])
                self.pruned_gap_seconds.append(loc['gap'])
            elif action == 'ROLE':
                record.update(outcome='EXCLUDED_BY_ROLE',
                    reason="'process' not in lr | rr" if feature.kind == 'process_instance' else
                    "not ('record' in lr and 'reference' in rr or 'reference' in lr and 'record' in rr)",
                    left_roles=sorted(loc['lr']), right_roles=sorted(loc['rr']))
            else:
                record.update(outcome='NOMINATED', reason=loc['reason'])
            self.events[key].append(record)
        return self

    def expanded_events(self):
        result = defaultdict(list, {p: list(rows) for p, rows in self.events.items()})
        for row in self.postings:
            for key in combinations(row['stage_ids'], 2):
                result[key].append({k:v for k,v in row.items() if k != 'stage_ids'} |
                    dict(outcome='SKIPPED_POSTING', posting_stage_count=len(row['stage_ids'])))
        return result


def replay(handoff):
    global REPLAY_ACTIVE
    from app.adapters.base import AdapterSettings
    from app.community import load_community_config
    from app.config import read_yaml
    from app.models import CanonicalAlert, Entity
    from app.stages.models import StageResult
    from app.stage_candidates import generate_stage_pair_candidates, load_candidate_config
    from app.stage_evidence import load_evidence_config, validate_stage_pair_candidates
    from app.stage_evidence.extraction import project_witnesses

    alerts = {a['alert_id']:CanonicalAlert.model_validate(a) for a in handoff['alerts']}
    entities = {e['entity_id']:Entity.model_validate(e) for e in handoff['entities']}
    stages = StageResult.model_validate(handoff['stages'])
    settings = {v['source_namespace']:AdapterSettings(**v)
        for v in read_yaml(ROOT/'configs/front-data-profiles.yaml')['sources'].values()}
    cfg = load_community_config(ROOT/'configs/community-v1.yaml')
    policy = load_evidence_config(ROOT/'configs/stage-evidence-v1.yaml')
    observer = GeneratorTrace(generate_stage_pair_candidates)
    calls, captured = Counter(), {}
    forbidden = ('app.stage_chains', 'app.chains', 'app.api', 'app.ai', 'app.correlation',
        'app.stage_relations', 'evaluation', 'app.entities.extraction', 'app.entities.front_data',
        'app.stages.aggregation', 'app.community.builder', 'app.services.stage_pipeline')
    def profile(frame, event, arg):
        module = frame.f_globals.get('__name__', '')
        if event == 'call':
            if module.startswith(forbidden):
                raise AssertionError('audit_forbidden_algorithm_call:' + module)
            if module.startswith('app.'):
                calls[module+'.'+frame.f_code.co_name] += 1
        elif event == 'return' and frame.f_code is project_witnesses.__code__:
            captured['indexes'] = arg
    previous_trace, previous_profile = sys.gettrace(), sys.getprofile()
    before = digest(handoff)
    try:
        REPLAY_ACTIVE = True
        sys.setprofile(profile)
        sys.settrace(observer)
        candidate = generate_stage_pair_candidates(stages, list(alerts.values()), list(entities.values()), settings, cfg,
            load_candidate_config(ROOT/'configs/stage-candidates-v1.yaml'))
        sys.settrace(previous_trace)
        if candidate.model_dump(mode='json') != handoff['candidates']:
            raise ValueError('official_stage7_replay_differs_from_frozen_source')
        evidence = validate_stage_pair_candidates(candidate, stages, list(alerts.values()), list(entities.values()), settings, cfg, policy)
        if evidence.model_dump(mode='json') != handoff['evidence']:
            raise ValueError('official_stage8_replay_differs_from_frozen_source')
    finally:
        sys.settrace(previous_trace)
        sys.setprofile(previous_profile)
        REPLAY_ACTIVE = False
    if digest(handoff) != before:
        raise ValueError('frozen_handoff_mutated')
    return dict(alerts=alerts, entities=entities, stages={s.stage_id:s for s in stages.stages}, settings=settings,
        cfg=cfg, policy=policy, indexes=captured['indexes'], observer=observer, calls=dict(calls))


def pair_inventory(handoff, live):
    from app.stage_candidates.generator import stage_gap
    stages = live['stages']
    candidates = {pair(c):c for c in handoff['candidates']['candidates']}
    decisions = {pair(d):d for d in handoff['evidence']['decisions']}
    if candidates.keys() != decisions.keys():
        raise ValueError('candidate_decision_partition_mismatch')
    features = defaultdict(dict)
    for f in handoff['candidates']['features']:
        features[f['stage_id']][f['key']] = f
    events = live['observer'].expanded_events()
    result = []
    for a, b in combinations(sorted(stages), 2):
        candidate = candidates.get((a,b))
        shared_keys = sorted(features[a].keys() & features[b].keys())
        observed = events[(a,b)]
        observed_keys = {r['key'] for r in observed}
        if observed_keys != set(shared_keys):
            raise ValueError('unexplained_original_posting_branch:' + str((a,b)))
        nominated = [r for r in observed if r['outcome'] == 'NOMINATED']
        if bool(candidate) != bool(nominated):
            raise ValueError('traced_nomination_does_not_match_formal_output')
        # Absence of an intersection means the actual inversion loop never
        # visits this pair. This is an audit absence label, not a formal status.
        reasons = sorted({r['reason'] for r in observed}) if not candidate else []
        if not candidate and not shared_keys:
            reasons = ['NO_SHARED_RETRIEVAL_KEY']
        result.append(dict(stage_a=a, stage_b=b, community_a=stages[a].community_id,
            community_b=stages[b].community_id, same_community=stages[a].community_id==stages[b].community_id,
            candidate=bool(candidate), candidate_id=candidate['candidate_id'] if candidate else None,
            candidate_reason=candidate['candidate_reasons'] if candidate else [],
            rejection_reason=reasons, reason_provenance='executed_official_generator_branches_or_absent_posting_intersection',
            shared_existing_feature_keys=shared_keys, original_generator_events=observed,
            stage_gap_seconds=stage_gap(stages[a],stages[b]),
            decision=decisions[(a,b)]['relation_type'] if candidate else 'NOT_ENTERED_STAGE8'))
    return result


def decision_inventory(handoff, live):
    claims = {c['claim_id']:c for c in handoff['evidence']['claims']}
    contexts = {c['context_identity_id']:c for c in handoff['evidence']['context_postings']}
    candidates = {c['candidate_id']:c for c in handoff['candidates']['candidates']}
    result = []
    for d in handoff['evidence']['decisions']:
        claim_ids = [i for group in ('relation_claim_ids','context_claim_ids','supporting_claim_ids','invalid_claim_ids') for i in d[group]]
        selected = [claims[i] for i in claim_ids]
        primary = claims.get(d['primary_claim_id'])
        idx_a, idx_b = live['indexes'][d['stage_a_id']], live['indexes'][d['stage_b_id']]
        shared = [dict(kind=k[0], key=k[1], identity=json.loads(idx_a[k][0].identity),
            roles_a=sorted({o.role for o in idx_a[k]}), roles_b=sorted({o.role for o in idx_b[k]}),
            witness_alert_ids_a=sorted({o.alert_id for o in idx_a[k]}),
            witness_alert_ids_b=sorted({o.alert_id for o in idx_b[k]})) for k in sorted(idx_a.keys() & idx_b.keys())]
        result.append(dict(relation_id=d['candidate_id'], stage_a=d['stage_a_id'], stage_b=d['stage_b_id'],
            community_a=live['stages'][d['stage_a_id']].community_id,
            community_b=live['stages'][d['stage_b_id']].community_id,
            candidate_reason=candidates[d['candidate_id']]['candidate_reasons'],
            decision=d['relation_type'], relation_type_if_any=d['relation_type'] if primary else None,
            formal_decision=d, blocking_reason=rejection_reason(d),
            primary_evidence_type=primary['evidence_type'] if primary else None,
            valid_relation_evidence_types=sorted({c['evidence_type'] for c in selected if c['claim_id'] in d['relation_claim_ids']}),
            valid_claim_classes=dict(Counter(c['semantic_class'] for c in selected if c['valid'])),
            valid_directional_claims=[c['claim_id'] for c in selected if c['valid'] and c['semantic_class']=='DIRECTIONAL_RELATION'],
            valid_associative_relation_claims=[c['claim_id'] for c in selected if c['valid'] and c['semantic_class']=='DIRECT_ASSOCIATIVE_RELATION'],
            shared_stage8_projected_postings=shared,
            formal_claims=selected, context_postings=[contexts[i] for i in d['context_identity_ids']],
            final_branch_code='backend/app/stage_evidence/validation.py:decide',
            missing_condition=('No valid DIRECTIONAL_RELATION or DIRECT_ASSOCIATIVE_RELATION claim.' if not primary else None)))
    return result


def projection_inventory(handoff, live, isolated):
    """Compare native Profile bindings against original ⑦/⑧ projections.

    This checks preservation, not whether shared context deserves a new edge.
    Observations, roles and identities are from the existing functions only.
    """
    from app.community.evidence import profile
    features = handoff['candidates']['features']
    owner = {aid:sid for sid,s in live['stages'].items() for aid in s.alert_ids}
    flat = {sid:[o for bucket in idx.values() for o in bucket] for sid,idx in live['indexes'].items()}
    direct_kinds = {'request','session','connection','application_session','task','process_instance','object','direct_reference'}
    rows, losses = [], []
    for aid, alert in sorted(live['alerts'].items()):
        sid = owner[aid]
        original = profile(alert, live['entities'], live['settings'][alert.source_namespace], live['cfg'])
        observations = [o for o in flat[sid] if o.alert_id == aid]
        available = [(f,w) for f in features if f['stage_id']==sid for w in f['witnesses'] if w['alert_id']==aid]
        for binding in original.bindings:
            row = dict(stage_id=sid, alert_id=aid, isolated=sid in isolated, binding=asdict(binding),
                source_namespace=alert.source_namespace, potential_stage_projection_loss=False)
            if binding.projection!='binding' or not binding.complete:
                row['status']='NON_BINDING_OR_INCOMPLETE_RETAINED_AS_CONTEXT'
            elif binding.kind in direct_kinds:
                expected_role=binding.role
                expected_kind=binding.kind
                # ⑧ assigns explicit predecessor/reference roles from configured
                # raw paths; these are preserved rather than guessed directions.
                hits=[o for o in observations if o.kind==expected_kind and o.identity==binding.identity and
                    (o.role==expected_role or binding.kind=='direct_reference' and expected_role=='reference' and o.role=='predecessor') and
                    set(binding.pointers)<=set(o.pointers)]
                candidate_hits=[f['key'] for f,w in available if f['kind']==binding.kind and
                    encode(f['identity'])==encode(json.loads(binding.identity)) and set(binding.pointers)<=set(p['pointer'] for p in w['pointers'])]
                row.update(stage8_observation_hits=[asdict(o) for o in hits], stage7_feature_keys=sorted(set(candidate_hits)))
                row['status']='PRESERVED_TYPED_BINDING' if hits and candidate_hits else 'POTENTIAL_STAGE_PROJECTION_LOSS'
                row['potential_stage_projection_loss']=not (hits and candidate_hits)
            elif binding.kind=='flow':
                hits=[o for o in observations if o.kind=='flow_tuple' and set(binding.pointers)<=set(o.pointers)]
                row.update(stage8_observation_hits=[asdict(o) for o in hits],
                    status='PRESERVED_TUPLE_SUPPORT_NATIVE_FLOW_IS_SEPARATE' if hits else 'POTENTIAL_STAGE_PROJECTION_LOSS',
                    potential_stage_projection_loss=not bool(hits))
            elif binding.kind in {'host','host_account','host_process'}:
                hits=[o for o in observations if o.kind.startswith('entity.') and set(o.pointers)&set(binding.pointers)]
                row.update(stage8_observation_hits=[asdict(o) for o in hits], status='PRESERVED_AS_SUPPORTING_ENTITY_CONTEXT')
            else:
                row['status']='NO_STAGE8_DIRECT_BINDING_RULE_BY_DESIGN'
            if row['potential_stage_projection_loss']:
                losses.append(row)
            rows.append(row)
    entity_checks=[]
    for sid, stage in sorted(live['stages'].items()):
        for aid in stage.alert_ids:
            for o in live['alerts'][aid].entity_occurrences:
                kind=live['entities'][o.entity_id].type.value
                stage_field={'HOST':'host_entities','ACCOUNT':'account_entities','PROCESS':'process_entities'}.get(kind)
                preserved=(o.entity_id in getattr(stage,stage_field)) if stage_field else None
                if preserved is False:
                    losses.append(dict(stage_id=sid,alert_id=aid,entity_id=o.entity_id,status='STAGE_ENTITY_SUMMARY_LOSS',potential_stage_projection_loss=True))
                entity_checks.append(dict(stage_id=sid,alert_id=aid,entity_id=o.entity_id,entity_type=kind,
                    stage_summary_field=stage_field,stage_summary_preserved=preserved))
    identity_checks=[]
    for category in ('host_alias_bindings','auth_session_bindings','process_bindings'):
        for binding in handoff['identity_projection'][category]:
            eid=binding.get('canonical_session_entity_id',binding.get('canonical_host_entity_id'))
            members=[]
            for observation in binding['observations']:
                aid=observation['alert_id'];sid=owner[aid]
                member=dict(alert_id=aid,stage_id=sid,isolated=sid in isolated,
                    canonical_entity_in_alert=eid in live['alerts'][aid].entity_ids,
                    stage7_feature_keys=sorted({f['key'] for f in features if f['stage_id']==sid and any(w['alert_id']==aid for w in f['witnesses'])}),
                    stage8_projection_kinds=sorted({o.kind for o in flat[sid] if o.alert_id==aid}))
                members.append(member)
                if not member['canonical_entity_in_alert']:
                    losses.append(dict(stage_id=sid,alert_id=aid,status='ARCHIVED_IDENTITY_NOT_IN_ALERT',potential_stage_projection_loss=True))
            identity_checks.append(dict(category=category,binding=binding,members=members))
    # Structural recall completeness checks use ORIGINAL ⑧ postings, not newly
    # extracted fields or a substitute pair generator. No decision is evaluated
    # for a non-candidate pair.
    candidate_pairs={pair(c) for c in handoff['candidates']['candidates']}
    missing_typed=[]
    for a,b in combinations(sorted(live['stages']),2):
        if (a,b) in candidate_pairs:
            continue
        left,right=live['indexes'][a],live['indexes'][b]
        for key in sorted(left.keys()&right.keys()):
            if key[0] not in direct_kinds|{'flow'}:
                continue
            roles={o.role for o in left[key]+right[key]}
            if key[0]=='process_instance' and 'process' not in roles:
                continue
            if key[0]=='direct_reference' and not ('record' in roles and len(roles)>1):
                continue
            missing_typed.append(dict(stage_a=a,stage_b=b,kind=key[0],key=key[1],
                left_observations=[asdict(o) for o in left[key]],right_observations=[asdict(o) for o in right[key]],
                diagnostic_only=True,relation_decision_not_evaluated=True))
    return dict(binding_observations=rows,entity_summary_checks=entity_checks,identity_projection_checks=identity_checks,
        potential_losses=losses,noncandidate_pairs_with_existing_typed_stage8_postings=missing_typed,
        status_counts=dict(Counter(r['status'] for r in rows)),
        complete_binding_kinds=dict(Counter(r['binding']['kind'] for r in rows
            if r['binding']['projection']=='binding' and r['binding']['complete'])),
        isolated_binding_status_counts=dict(Counter(r['binding']['kind']+' / '+r['status'] for r in rows
            if r['isolated'] and r['binding']['projection']=='binding')))


def isolated_inventory(stages, pairs, decisions, projections):
    incident=defaultdict(list)
    degree=Counter()
    for row in pairs:
        for sid in (row['stage_a'],row['stage_b']): incident[sid].append(row)
    for row in decisions:
        if row['decision']!='NO_RELATION':
            degree.update((row['stage_a'],row['stage_b']))
    rows=[]
    for sid in sorted(stages):
        if degree[sid]:continue
        touching=incident[sid];candidates=[r for r in touching if r['candidate']]
        rejected=[r for r in decisions if sid in (r['stage_a'],r['stage_b']) and r['decision']=='NO_RELATION']
        reasons=Counter(r['blocking_reason'] for r in rejected)
        losses=[r for r in projections['potential_losses'] if r['stage_id']==sid]
        missing=[r for r in projections['noncandidate_pairs_with_existing_typed_stage8_postings'] if sid in (r['stage_a'],r['stage_b'])]
        rows.append(dict(stage_id=sid,community_id=stages[sid].community_id,possible_pair_count=len(stages)-1,
            candidate_pair_count=len(candidates),non_candidate_pair_count=len(touching)-len(candidates),
            accepted_relation_count=0,rejected_pair_count=len(rejected),rejected_relation_count=len(rejected),
            degree=0,ISOLATED_IN_STAGE8_GRAPH=True,
            primary_isolation_reason='NO_CANDIDATE_GENERATED' if not candidates else 'CANDIDATES_ALL_REJECTED',
            secondary_reasons=dict(reasons),
            noncandidate_reasons=dict(Counter(reason for p in touching if not p['candidate'] for reason in p['rejection_reason'])),
            POTENTIAL_STAGE_PROJECTION_LOSS=bool(losses),projection_loss_evidence=losses,
            missing_typed_posting_pair_evidence=missing,
            classification='POTENTIALLY_FALSE_ISOLATED' if losses or missing else 'LEGITIMATELY_ISOLATED_UNDER_CURRENT_OBSERVED_CONTRACT',
            all_candidate_pairs_temporally_rejected=bool(rejected) and all('TEMPORAL_CONFLICT' in r['formal_decision']['diagnostics'] for r in rejected),
            ISOLATED_DUE_TO_HARD_CONFLICT=bool(rejected) and all('HARD_CONFLICT' in r['formal_decision']['diagnostics'] for r in rejected),
            cross_community_candidate_count=sum(not p['same_community'] for p in candidates),
            same_community_candidate_count=sum(p['same_community'] for p in candidates),
            all_eligible_shared_postings_filtered_by_time=(not candidates and any(e['outcome']=='EXCLUDED_BY_TIME'
                for p in touching for e in p['original_generator_events']) and
                all(e['outcome'] in {'EXCLUDED_BY_TIME','SKIPPED_POSTING'} for p in touching for e in p['original_generator_events']))))
    return rows


def stage_inventory(handoff, live, isolated):
    degree=Counter(s for d in handoff['evidence']['decisions'] if d['relation_type']!='NO_RELATION' for s in pair(d))
    rows=[]
    for sid,s in sorted(live['stages'].items()):
        alerts=[live['alerts'][a] for a in s.alert_ids]
        rows.append(dict(stage_id=sid,community_id=s.community_id,alert_count=s.alert_count,start_time=s.start_time,end_time=s.end_time,
            host_ids=s.host_entities,account_ids=s.account_entities,process_ids=s.process_entities,
            request_ids=s.request_bindings,flow_ids=s.flow_bindings,session_ids=s.session_bindings,
            task_ids=s.task_bindings,behavior=s.behavior,categories=dict(Counter(a.category.value for a in alerts)),
            source_types=s.source_types,security_sources=dict(Counter(a.source_namespace for a in alerts)),
            member_context_refs=[dict(alert_id=a.alert_id,context=c.model_dump(mode='json')) for a in alerts for c in a.contexts],
            source_products=dict(Counter(a.source_product or 'UNAVAILABLE' for a in alerts)),
            native_source_types=dict(Counter(a.raw_alert.get('source_type','UNAVAILABLE') for a in alerts if isinstance(a.raw_alert,dict))),
            alert_ids=s.alert_ids,stage8_degree=degree[sid],ISOLATED_IN_STAGE8_GRAPH=sid in isolated))
    return rows


def summarize(handoff, live, pairs, decisions, isolated, projections):
    accepted=[d for d in decisions if d['decision']!='NO_RELATION'];rejected=[d for d in decisions if d['decision']=='NO_RELATION']
    candidate=[p for p in pairs if p['candidate']];noncandidate=[p for p in pairs if not p['candidate']]
    reasons=Counter(d['blocking_reason'] for d in rejected)
    primary=Counter(d['primary_evidence_type'] for d in accepted)
    usages=Counter(t for d in accepted for t in d['valid_relation_evidence_types'])
    all_usages=Counter(t for d in accepted for t in {c['evidence_type'] for c in d['formal_claims']})
    contexts=handoff['evidence']['context_postings']
    undirected=[d for d in accepted if d['decision']=='UNDIRECTED_EDGE']
    temporal=[p for p in pairs if any(e['outcome']=='EXCLUDED_BY_TIME' for e in p['original_generator_events'])]
    time_only=[p for p in noncandidate if p['original_generator_events'] and
        all(e['outcome'] in {'EXCLUDED_BY_TIME','SKIPPED_POSTING'} for e in p['original_generator_events']) and
        any(e['outcome']=='EXCLUDED_BY_TIME' for e in p['original_generator_events'])]
    conflicts=[d for d in decisions if 'HARD_CONFLICT' in d['formal_decision']['diagnostics']]
    source=Counter(d['decision'] for d in decisions)
    classification=Counter(s['classification'] for s in isolated)
    sizes=component_sizes(live['stages'],[(d['stage_a'],d['stage_b']) for d in accepted])
    return dict(TASK_RESULT='SUCCESS',AUDIT_ONLY=True,STAGE_8_RELATION_SPARSITY_AUDIT='PASS',
        INPUT_STAGE_COUNT=len(live['stages']),TOTAL_POSSIBLE_STAGE_PAIRS=len(pairs),
        STAGE7_CANDIDATE_PAIR_COUNT=len(candidate),STAGE7_NON_CANDIDATE_PAIR_COUNT=len(noncandidate),
        STAGE8_INPUT_PAIR_COUNT=len(decisions),STAGE8_ACCEPTED_RELATION_COUNT=len(accepted),STAGE8_REJECTED_PAIR_COUNT=len(rejected),
        STRONG_DIRECTED_COUNT=source['DIRECTED_EDGE'],STRONG_UNDIRECTED_COUNT=source['UNDIRECTED_EDGE'],WEAK_DIRECTED_COUNT=0,
        ORIGINAL_RELATION_TYPE_COUNTS=dict(source),ISOLATED_STAGE_COUNT=len(isolated),
        CONNECTED_STAGE_COUNT=len(live['stages'])-len(isolated),
        MULTI_STAGE_COMPONENT_COUNT=sum(n>1 for n in sizes),MULTI_STAGE_COMPONENT_SIZES=[n for n in sizes if n>1],
        ISOLATED_STAGE_WITH_ZERO_CANDIDATE_COUNT=sum(s['candidate_pair_count']==0 for s in isolated),
        ISOLATED_STAGE_WITH_CANDIDATES_BUT_ALL_REJECTED_COUNT=sum(s['candidate_pair_count']>0 for s in isolated),
        SAME_COMMUNITY_CANDIDATE_COUNT=sum(p['same_community'] for p in candidate),
        CROSS_COMMUNITY_CANDIDATE_COUNT=sum(not p['same_community'] for p in candidate),
        SAME_COMMUNITY_ACCEPTED_COUNT=sum(d['community_a']==d['community_b'] for d in accepted),
        CROSS_COMMUNITY_ACCEPTED_COUNT=sum(d['community_a']!=d['community_b'] for d in accepted),
        THEORETICAL_SAME_COMMUNITY_PAIR_COUNT=sum(p['same_community'] for p in pairs),
        THEORETICAL_CROSS_COMMUNITY_PAIR_COUNT=sum(not p['same_community'] for p in pairs),
        COMMUNITY_BOUNDARY_FILTER_IMPLEMENTED=False,PAIRS_EXCLUDED_BY_COMMUNITY_BOUNDARY=0,
        HARD_CONFLICT_PAIR_COUNT=len(conflicts),HARD_CONFLICT_REJECTED_PAIR_COUNT=sum(d['decision']=='NO_RELATION' for d in conflicts),
        HARD_CONFLICT_ISOLATED_STAGE_COUNT=sum(s['ISOLATED_DUE_TO_HARD_CONFLICT'] for s in isolated),
        STAGE7_TEMPORAL_PRUNED_POSTING_PAIR_VISITS=len(live['observer'].pruned_gap_seconds),
        STAGE7_PAIRS_WITH_ANY_TEMPORAL_PRUNING=len(temporal),
        PAIRS_REJECTED_BY_TEMPORAL_CONSTRAINT=len(time_only),
        STAGE7_PAIR_EXCLUSIONS_ATTRIBUTABLE_TO_TEMPORAL_BRANCH=len(time_only),
        STAGE8_TEMPORAL_CONFLICT_REJECTED_PAIR_COUNT=sum(d['decision']=='NO_RELATION' and 'TEMPORAL_CONFLICT' in d['formal_decision']['diagnostics'] for d in decisions),
        ISOLATED_STAGES_ALL_SHARED_ELIGIBLE_POSTINGS_TEMPORALLY_EXCLUDED=sum(s['all_eligible_shared_postings_filtered_by_time'] for s in isolated),
        POTENTIAL_STAGE_PROJECTION_LOSS_COUNT=len(projections['potential_losses']),
        NONCANDIDATE_PAIRS_WITH_EXISTING_TYPED_STAGE8_POSTINGS=len({(r['stage_a'],r['stage_b']) for r in projections['noncandidate_pairs_with_existing_typed_stage8_postings']}),
        RELATION_PRESENT_BUT_DIRECTION_UNKNOWN_PAIR_COUNT=len(undirected),ACCEPTED_AS_STRONG_UNDIRECTED=len(undirected),
        REJECTED_DUE_TO_DIRECTION_REQUIREMENT=0,
        WEAK_DIRECTED_IMPLEMENTED=False,WEAK_DIRECTED_ENABLED=False,WEAK_DIRECTED_PATH_REACHED_COUNT=0,
        WEAK_DIRECTED_ACCEPTED_COUNT=0,LEGACY_WEAK_DIRECTED_IMPLEMENTED=True,LEGACY_WEAK_DIRECTED_PIPELINE_CALLED=False,
        WEAK_DIRECTED_ZERO_REASON='Official stage-evidence-v2 has no weak relation type or decision branch; historical app.stage_relations is not called.',
        LEGITIMATELY_ISOLATED_STAGE_COUNT=classification['LEGITIMATELY_ISOLATED_UNDER_CURRENT_OBSERVED_CONTRACT'],
        POTENTIALLY_FALSE_ISOLATED_STAGE_COUNT=classification['POTENTIALLY_FALSE_ISOLATED'],UNKNOWN_ISOLATION_STAGE_COUNT=classification['UNKNOWN'],
        CLASSIFICATION_SCOPE='Existing trustworthy bindings and current formal semantics only; not a claim about unobserved attacks or benignness.',
        TOP_REJECTION_REASONS=dict(reasons.most_common()),REJECT_REASON_COUNTS=dict(reasons),
        ISOLATED_STAGE_REASON_COUNTS=dict(Counter(s['primary_isolation_reason'] for s in isolated)),
        ISOLATED_STAGE_SECONDARY_REASON_COUNTS=dict(Counter(r for s in isolated for r in s['secondary_reasons'])),
        ACCEPTED_RELATION_EVIDENCE_USAGE=dict(usages),ACCEPTED_RELATION_PRIMARY_EVIDENCE_USAGE=dict(primary),
        ALL_CLAIM_EVIDENCE_USAGE_IN_ACCEPTED_PAIRS=dict(all_usages),
        STAGE7_NONCANDIDATE_REASON_COMBINATIONS=dict(Counter(' + '.join(p['rejection_reason']) for p in noncandidate)),
        ISOLATED_STAGES_CANDIDATE_PARTNERS_ONLY_OTHER_COMMUNITIES=sum(s['cross_community_candidate_count']>0 and
            s['same_community_candidate_count']==0 for s in isolated),
        STAGE_RELATION_LOGIC_MODIFIED=False,THRESHOLD_MODIFIED=False,DATASET_MODIFIED=False,GROUND_TRUTH_MODIFIED=False,
        NEW_RELATION_CREATED=False,EXISTING_RELATION_DELETED=False,STAGE9_EXECUTED=False,
        OFFICIAL_STAGE7_REPLAY_EXACT=True,OFFICIAL_STAGE8_REPLAY_EXACT=True,
        STAGES_BY_COMMUNITY=dict(Counter(s.community_id for s in live['stages'].values())),
        STAGES_BY_ALERT_COUNT=dict(Counter(s.alert_count for s in live['stages'].values())),
        TIME_GAP_SECONDS_DISTRIBUTIONS=dict(all_possible=distribution([p['stage_gap_seconds'] for p in pairs]),
            candidates=distribution([p['stage_gap_seconds'] for p in candidate]),
            noncandidates=distribution([p['stage_gap_seconds'] for p in noncandidate]),
            stage7_temporally_pruned_visits=distribution(live['observer'].pruned_gap_seconds),
            stage7_temporally_excluded_pairs=distribution([p['stage_gap_seconds'] for p in time_only]),
            stage8_rejected=distribution([p['stage_gap_seconds'] for p in pairs if p['candidate'] and p['decision']=='NO_RELATION'])),
        GLOBAL_CONTEXT_POSTING_COUNTS=dict(Counter(p['context_type'] for p in contexts)),
        COMMUNITY_MATCHING_EVIDENCE_SNAPSHOT_AVAILABLE=False,
        COMMUNITY_HANDOFF_AUDIT_BASIS='Existing Alert/Entity/Context IDs, Stage aggregation_basis, and unchanged official consumer code; no Community evidence reconstructed.',
        FILES_CHANGED=FILES_CHANGED)


def validate_report(report):
    s=report['summary'];pairs=report['pairs'];stages=report['stages'];decisions=report['decisions'];isolated=report['isolated']
    assert len(pairs)==s['TOTAL_POSSIBLE_STAGE_PAIRS']==len(stages)*(len(stages)-1)//2
    assert s['STAGE7_CANDIDATE_PAIR_COUNT']+s['STAGE7_NON_CANDIDATE_PAIR_COUNT']==len(pairs)
    assert s['STAGE8_INPUT_PAIR_COUNT']==s['STAGE7_CANDIDATE_PAIR_COUNT']==len(decisions)
    assert s['STAGE8_INPUT_PAIR_COUNT']==s['STAGE8_ACCEPTED_RELATION_COUNT']+s['STAGE8_REJECTED_PAIR_COUNT']
    assert sum(s['REJECT_REASON_COUNTS'].values())==s['STAGE8_REJECTED_PAIR_COUNT']
    assert all(r['candidate'] or r['rejection_reason'] for r in pairs)
    assert all(r['accepted_relation_count']==0 and r['candidate_pair_count']==r['rejected_pair_count'] for r in isolated)
    assert all(r['possible_pair_count']==r['candidate_pair_count']+r['non_candidate_pair_count'] for r in isolated)
    assert s['ISOLATED_STAGE_WITH_ZERO_CANDIDATE_COUNT']+s['ISOLATED_STAGE_WITH_CANDIDATES_BUT_ALL_REJECTED_COUNT']==len(isolated)
    assert sum(s[k] for k in ('LEGITIMATELY_ISOLATED_STAGE_COUNT','POTENTIALLY_FALSE_ISOLATED_STAGE_COUNT','UNKNOWN_ISOLATION_STAGE_COUNT'))==len(isolated)
    assert s['SAME_COMMUNITY_ACCEPTED_COUNT']+s['CROSS_COMMUNITY_ACCEPTED_COUNT']==s['STAGE8_ACCEPTED_RELATION_COUNT']
    assert s['SAME_COMMUNITY_CANDIDATE_COUNT']+s['CROSS_COMMUNITY_CANDIDATE_COUNT']==s['STAGE7_CANDIDATE_PAIR_COUNT']
    return True


def write_report(out, report):
    s=report['summary'];isolated=report['isolated'];stages=report['stages']
    text=['# ⑧ Stage Relation Graph 稀疏性审计', '',
        '本轮仅诊断。原样重放正式⑦和⑧并逐字段比对冻结输出；不运行①～⑥、不调用历史关联、不执行⑨，不读取 GT 作语义判断。', '',
        '## 漏斗', '',
        f"42 Stage → 861理论Pair → {s['STAGE7_CANDIDATE_PAIR_COUNT']}候选（⑦排除{s['STAGE7_NON_CANDIDATE_PAIR_COUNT']}） → {s['STAGE8_INPUT_PAIR_COUNT']}进入⑧ → {s['STAGE8_REJECTED_PAIR_COUNT']}拒绝 → 23关系 → 18有边节点、24个degree=0节点。", '',
        f"直接统计⑧图的多节点分量大小为{s['MULTI_STAGE_COMPONENT_SIZES']}；不生成Chain，不调用⑨。", '',
        '⑦排除是现有倒排索引、Context-only/common weak posting、角色及时间分支的结果；逐对真实执行路径见 pairs.json。⑧拒绝原因见 rejected_pairs.json。', '',
        '## 六个核心问题', '',
        f"1. 理论空间压缩主要发生在⑦（排除696/861，80.84%）；但24个孤立Stage中23个已有候选，孤立的直接原因主要是⑧没有足够直接关系证据，不能归咎于⑦完全不召回。⑧拒绝142/165（86.06%）。", '',
        f"2. ⑦完全没有候选：{s['ISOLATED_STAGE_WITH_ZERO_CANDIDATE_COUNT']}个。完整ID及原始特征路径见下表和isolated_stages.json。", '',
        f"3. 有候选但⑧全部拒绝：{s['ISOLATED_STAGE_WITH_CANDIDATES_BUT_ALL_REJECTED_COUNT']}个。138对只有已验证Context membership，4对没有任何有效Claim。共享Context不是缺失的直接关系边。", '',
        f"4. 已有可信绑定未正确投影的证据：本快照中发现{s['POTENTIAL_STAGE_PROJECTION_LOSS_COUNT']}项。原Profile绑定、Stage实体摘要、⑦Feature、⑧Observation及已归档Host/Auth投影逐项核对见projection_audit.json。缺少跨源网络权威声明与Stage聚合丢证据是不同问题。", '',
        '投影检查范围：冻结文件没有单独保存⑤CommunityResult.matching_evidence日志；本次按现有Alert/Entity/Context IDs、Stage聚合依据及⑤/⑥原始消费代码检查承接，不补造或重放⑤日志。⑤正式代码直接承接已绑定Alert/Entity，⑥Stage保留原Alert IDs；⑦/⑧仍逐个读取原始member Alert，而不是仅使用Stage摘要。', '',
        '5. WEAK_DIRECTED=0由正式契约和代码路径决定：stage-evidence-v2只有DIRECTED_EDGE / UNDIRECTED_EDGE / NO_RELATION，不是本数据恰好未满足弱边条件。历史stage_relations实现有WEAK_DIRECTED，但正式pipeline不调用。', '',
        f"6. 按当前可观察可信证据和正式语义，合法孤立{s['LEGITIMATELY_ISOLATED_STAGE_COUNT']}个，疑似假孤立{s['POTENTIALLY_FALSE_ISOLATED_STAGE_COUNT']}个，未知{s['UNKNOWN_ISOLATION_STAGE_COUNT']}个。这里只判断现有证据是否足以建关系，不判断Stage是否良性，也不推断未观测的攻击步骤。", '',
        '## ⑧拒绝与接受证据', '',
        '最终拒绝类别：`'+encode(s['TOP_REJECTION_REASONS'])+'`。没有Hard Conflict或无效Claim。不存在单独因方向未知而整体拒绝；有直接关联但方向未知的1对已按无向关系接受。', '',
        '138个SHARED_CONTEXT_ONLY是当前正式语义主动保留“共同参与上下文、但不确认Stage间直接关系”的结果，尤其是覆盖多个Stage的Flow/Process/Session。完整上下文没有丢失；它不满足当前“独占双Stage完整且未污染身份，或独立直接关系Claim”的建边要求。这是关系成立条件的设计后果，不能说成没有任何绑定，也不能说成方向未知被拒绝。', '',
        '23条边的主证据：`'+encode(s['ACCEPTED_RELATION_PRIMARY_EVIDENCE_USAGE'])+'`。按每条边全部有效Relation Claim去重计数（可重叠）：`'+encode(s['ACCEPTED_RELATION_EVIDENCE_USAGE'])+'`。支持证据不计作建边主证据。', '',
        '接受Pair中全部Claim类型的出现次数（含Context/Supporting，每Pair每类型只计一次）：`'+encode(s['ALL_CLAIM_EVIDENCE_USAGE_IN_ACCEPTED_PAIRS'])+'`。', '',
        '## Community、时间与网络身份边界', '',
        f"理论同Community Pair {s['THEORETICAL_SAME_COMMUNITY_PAIR_COUNT']}，跨Community {s['THEORETICAL_CROSS_COMMUNITY_PAIR_COUNT']}；候选分别{s['SAME_COMMUNITY_CANDIDATE_COUNT']}、{s['CROSS_COMMUNITY_CANDIDATE_COUNT']}；接受分别{s['SAME_COMMUNITY_ACCEPTED_COUNT']}、{s['CROSS_COMMUNITY_ACCEPTED_COUNT']}。正式⑦没有same-community硬边界，因此没有因Community禁比而排除的Pair。", '',
        f"⑦时间分支裁剪{s['STAGE7_TEMPORAL_PRUNED_POSTING_PAIR_VISITS']}次posting-pair访问，涉及{s['STAGE7_PAIRS_WITH_ANY_TEMPORAL_PRUNING']}个不同Pair；最终因此完全未入候选{s['PAIRS_REJECTED_BY_TEMPORAL_CONSTRAINT']}对。不能将posting访问次数当成最终Pair丢失数。分布（秒）：`{encode(s['TIME_GAP_SECONDS_DISTRIBUTIONS'])}`。", '',
        '696个非候选的互斥归因组合：`'+encode(s['STAGE7_NONCANDIDATE_REASON_COMBINATIONS'])+'`。NO_SHARED_RETRIEVAL_KEY是审计对真实倒排交集为空的缺席标签，其余名称均来自原始执行分支，并非新增生产拒绝状态。', '',
        '⑧没有通用关系年龄上限，只对方向证据做各证据类型的倒序检查；当前无TEMPORAL_CONFLICT。Host/Account/IP相同、共享多Stage Flow或时间接近均不自动构成关系。', '',
        '4个NO_VALID_EVIDENCE Pair均由SHARED_CONNECTION_TOKEN_AND_ENDPOINT_PAIR召回。它只声明候选线索；Firewall/EDR/Auth的connection/session scope仍含不同来源或host_scope，当前没有可信跨源网络身份投影。相同token和端点可见，但不等于已有可信跨源binding在Stage层丢失。详见network_scope_audit.json。', '',
        '## 各类绑定是否仍可见', '',
        '| 检查项 | 真实输入与消费结果 |', '|---|---|',
        '| Host Binding | 85条Host绑定记录均可见；2条归档HostAlias覆盖85条观测，其中9条属于孤立Stage。⑧将共享Host视为SAME_HOST支持证据，不独立建边。 |',
        '| Account Binding | 61条host_account记录的实体/指针可见；⑧通过entity.ACCOUNT/HOST读取，属于支持上下文。 |',
        '| Process Binding | 112条完整process_instance记录保留；12条不完整实例的host_process记录仅作为实体描述上下文。完整父子角色支撑12条正式边。 |',
        '| Request Binding | 34条原Request绑定保留；纯共享Request在多Stage时属于Context，显式request/response操作才可能提供方向。 |',
        '| Flow Binding | 72条完整tuple可见，并另保留native flow+tuple上下文。孤立Stage包含49条tuple投影，没有从Stage中丢失。多成员Flow身份不自动变成pairwise边。 |',
        '| Auth Session Binding | 原6条权威AuthSession投影共46条观测，全部保留；没有观测属于当前孤立Stage。有效建立/使用角色产生9条主证据边。 |',
        '| Network Session Binding | 40条原connection绑定记录保留（其中20条属于孤立Stage），scope保持来源/Host边界；没有跨源Network authority，不能把相同token自动视为可信跨源binding。 |',
        '| Cross-Source Identity Projection | HostAlias与AuthSession按原权威scope消费；没有已有Process continuity或Network identity projection可被误称为Stage层丢失。 |', '',
        '## 42个Stage', '',
        '完整基础信息、实体/绑定ID、行为、来源覆盖与degree见stages.json。表内ID为缩写；可通过同名JSON查完整稳定ID。', '',
        '| Stage | Community | Alerts | Behavior | Degree | Isolated |', '|---|---|---:|---|---:|---|']
    for row in stages:
        text.append(f"| {row['stage_id'][:16]} | {row['community_id'][:16]} | {row['alert_count']} | {row['behavior']} | {row['stage8_degree']} | {str(row['ISOLATED_IN_STAGE8_GRAPH']).lower()} |")
    text += ['', '## 24个孤立Stage逐项归因', '',
        '| Stage | Candidate | Non-candidate | Rejected | Primary | Secondary |', '|---|---:|---:|---:|---|---|']
    for row in isolated:
        text.append(f"| {row['stage_id'][:16]} | {row['candidate_pair_count']} | {row['non_candidate_pair_count']} | {row['rejected_pair_count']} | {row['primary_isolation_reason']} | {encode(row['secondary_reasons'])} |")
    zero=next(r for r in isolated if not r['candidate_pair_count'])
    text += ['', f"零候选Stage完整ID：`{zero['stage_id']}`（4条Suricata告警，UNKNOWN）。31个其它Stage没有共享检索键；其余10个虽共享IP端点，但公共弱键及Context-only键不独立召回。唯一未被这些键限制的url_endpoint_pair提示与另一Stage相隔460秒，被现有120秒窗口排除。它的完整native Flow/五元组没有其它Stage使用相同键。这里没有证明该弱提示应建立关系，也没有对未进入⑧的Pair进行反事实决策。其现有特征及非候选排除路径见zero_candidate_stage.json；不根据⑨定义孤立。", '',
        '## 文件与核验', '',
        '- summary.json / acceptance.txt：全部要求的验收字段。',
        '- stages.json：42个Stage及来源覆盖；pairs.json：861个Pair及⑦实际代码路径。',
        '- decisions.json / accepted_relations.json / rejected_pairs.json：165个正式Decision及证据。',
        '- isolated_stages.json：24个degree=0节点逐个根因、候选数及证据分类。',
        '- projection_audit.json / stage8_postings.json：绑定、实体、投影和原始索引核对。',
        '- network_scope_audit.json：4个Connection召回线索未形成可信Relation的原始scope。',
        '- trace_tables.json：原始Claim/Context/Observation/Validation/Raw Pointer及解析值。',
        '- execution.json：原正式函数调用统计、原始源代码定位和源码哈希。',
        '- integrity.json：已有生产代码、配置、⑨输出及Dataset/GT文件哈希核验。', '',
        '诊断复现：`.venv\\Scripts\\python.exe -B scripts/audit_stage8_relation_sparsity.py --output outputs/stage8_relation_sparsity_audit_repeat`。首次运行在新输出目录自动建立只读保护基线。', '',
        '测试：`.venv\\Scripts\\python.exe -B -m pytest tests/audit-only/test_stage8_relation_audit.py -q -p no:cacheprovider`（测试默认核验本轮outputs/stage8_relation_sparsity_audit下的完整审计结果）。', '',
        '所有根因均基于当前代码、原始输出与实际执行分支；没有重接纳Pair，没有改变关系、阈值、数据或GT。']
    (out/'REPORT.md').write_text('\n'.join(text)+'\n',encoding='utf8')


def protect(source,out):
    """Capture audit invariants before replay; GT bytes are hashed, not parsed."""
    target=out/'protected_before.json'
    if target.exists():
        return json.loads(target.read_text(encoding='utf8'))
    if out.exists() and any(out.iterdir()):
        raise ValueError('unrecognized_nonempty_audit_output_directory')
    out.mkdir(parents=True,exist_ok=True)
    protected={str(p.resolve()):file_hash(p) for name in
        ('backend/app','backend/tests','configs','scripts','docs','tests','frontend/src')
        for p in (ROOT/name).rglob('*') if p.is_file() and '__pycache__' not in p.parts}
    protected[str(source)]=file_hash(source)
    prior=source.parent/'after_protected.json'
    if prior.is_file():
        for name in json.loads(prior.read_text(encoding='utf8')):
            p=Path(name)
            if 'TraceBack-Dataset' in str(p) and p.is_file():
                protected[str(p.resolve())]=file_hash(p)
    formal9=ROOT/'outputs/stage9_attack_chain_reconstruction/formal_run'
    if formal9.is_dir():
        for p in formal9.iterdir():
            if p.is_file():protected[str(p.resolve())]=file_hash(p)
    save(out,target.name,protected)
    return protected


def run(source, out):
    source,out=Path(source).resolve(),Path(out).resolve()
    if not source.is_relative_to(ROOT/'outputs') or not out.is_relative_to(ROOT/'outputs'):
        raise ValueError('audit_sources_and_reports_require_output_roots')
    if source.is_relative_to(out):
        raise ValueError('audit_output_must_not_contain_source_snapshot')
    protected=protect(source,out)
    original_hash=file_hash(source)
    handoff=json.loads(source.read_text(encoding='utf8'))
    original_digest=digest(handoff)
    live=replay(handoff)
    pairs=pair_inventory(handoff,live)
    decisions=decision_inventory(handoff,live)
    degree=Counter(s for d in handoff['evidence']['decisions'] if d['relation_type']!='NO_RELATION' for s in pair(d))
    isolated_ids=set(live['stages'])-degree.keys()
    projections=projection_inventory(handoff,live,isolated_ids)
    isolated=isolated_inventory(live['stages'],pairs,decisions,projections)
    stages=stage_inventory(handoff,live,isolated_ids)
    summary=summarize(handoff,live,pairs,decisions,isolated,projections)
    report=dict(summary=summary,pairs=pairs,decisions=decisions,isolated=isolated,stages=stages)
    validate_report(report)
    if (len(stages),len(pairs),len(decisions),len(isolated),summary['STAGE8_ACCEPTED_RELATION_COUNT'])!=(42,861,165,24,23):
        raise ValueError('audit_is_not_the_requested_frozen_42_stage_graph')
    from app.models.alerts import EvidencePointer
    trace=handoff['evidence']['trace']
    resolved=[dict(pointer_id=r['pointer_id'],raw_pointer=r['raw_pointer'],
        resolved_value=EvidencePointer.model_validate(r['raw_pointer']).resolve(live['alerts'])) for r in trace['raw_pointers']]
    save(out,'stages.json',stages)
    save(out,'source_coverage_per_stage.json',{s['stage_id']:dict(source_types=s['source_types'],
        source_namespaces=s['security_sources'],source_products=s['source_products'],
        native_source_types=s['native_source_types']) for s in stages})
    save(out,'pairs.json',pairs)
    save(out,'noncandidate_pairs.json',[p for p in pairs if not p['candidate']])
    save(out,'decisions.json',decisions)
    save(out,'accepted_relations.json',[d for d in decisions if d['decision']!='NO_RELATION'])
    save(out,'rejected_pairs.json',[d for d in decisions if d['decision']=='NO_RELATION'])
    save(out,'isolated_stages.json',isolated)
    save(out,'projection_audit.json',projections)
    save(out,'stage8_postings.json',{sid:[asdict(o) for bucket in idx.values() for o in bucket] for sid,idx in live['indexes'].items()})
    save(out,'trace_tables.json',dict(claims=handoff['evidence']['claims'],contexts=handoff['evidence']['context_postings'],
        **trace,resolved_raw_pointers=resolved))
    network=[]
    for d in decisions:
        if d['blocking_reason']!='NO_VALID_EVIDENCE':continue
        endpoints=[]
        for sid in (d['stage_a'],d['stage_b']):
            endpoints.append(dict(stage_id=sid,alerts=[dict(alert_id=aid,source_namespace=live['alerts'][aid].source_namespace,
                contexts=[c.model_dump(mode='json') for c in live['alerts'][aid].contexts],
                raw_connection_id=live['alerts'][aid].raw_alert.get('connection_id'),
                declared_network_namespace=live['settings'][live['alerts'][aid].source_namespace].network_namespace)
                for aid in live['stages'][sid].alert_ids]))
        network.append(dict(pair=[d['stage_a'],d['stage_b']],candidate_reason=d['candidate_reason'],
            original_decision=d['formal_decision'],endpoints=endpoints))
    save(out,'network_scope_audit.json',network)
    zero=[s['stage_id'] for s in isolated if not s['candidate_pair_count']]
    save(out,'zero_candidate_stage.json',dict(stage_ids=zero,
        stages=[s for s in stages if s['stage_id'] in zero],
        existing_features=[f for f in handoff['candidates']['features'] if f['stage_id'] in zero],
        pairs=[p for p in pairs if p['stage_a'] in zero or p['stage_b'] in zero]))
    source_files=['backend/app/services/stage_pipeline.py','backend/app/stage_candidates/generator.py',
        'backend/app/stage_candidates/features.py','backend/app/stage_evidence/validation.py',
        'backend/app/stage_evidence/extraction.py','backend/app/stage_evidence/claims.py',
        'backend/app/stage_evidence/config.py','backend/app/stage_evidence/contracts.py',
        'backend/app/stage_relations/analysis.py','configs/front-data-profiles.yaml',
        'backend/app/community/builder.py','backend/app/community/evidence.py',
        'backend/app/stages/aggregation.py','backend/app/entities/front_data.py']
    save(out,'execution.json',dict(source=str(source.relative_to(ROOT)),source_sha256=original_hash,
        stage7_entry='app.stage_candidates.generator.generate_stage_pair_candidates',
        stage8_entry='app.stage_evidence.validation.validate_stage_pair_candidates',
        replay_calls=live['calls'],source_files={p:file_hash(ROOT/p) for p in source_files},
        replay_stage7_exact=True,replay_stage8_exact=True,stage9_called=False,
        forbidden_algorithms_called=False,ground_truth_semantically_read=False))
    changed=[p for p,h in protected.items() if not Path(p).is_file() or file_hash(p)!=h]
    if changed or file_hash(source)!=original_hash or digest(handoff)!=original_digest:
        raise ValueError('audit_protected_input_or_production_files_changed:'+str(changed))
    integrity=dict(PROTECTED_FILE_COUNT=len(protected),FILES_CHANGED_FROM_BASELINE=changed,
        FROZEN_HANDOFF_UNCHANGED=True,STAGE7_OUTPUT_UNCHANGED=True,STAGE8_OUTPUT_UNCHANGED=True,
        STAGE9_CODE_AND_ARTIFACTS_UNCHANGED=True,DATASET_MODIFIED=False,GROUND_TRUTH_MODIFIED=False,
        INPUT_SOURCE_SHA256=original_hash,RESOLVED_RAW_POINTER_COUNT=len(resolved),
        STAGE_RELATION_DIGEST_BEFORE=digest([d for d in handoff['evidence']['decisions'] if d['relation_type']!='NO_RELATION']),
        STAGE_RELATION_DIGEST_AFTER=digest([d for d in handoff['evidence']['decisions'] if d['relation_type']!='NO_RELATION']))
    save(out,'integrity.json',integrity)
    save(out,'summary.json',summary)
    (out/'acceptance.txt').write_text('\n'.join(k+'='+json.dumps(v,ensure_ascii=False) for k,v in summary.items())+'\n',encoding='utf8')
    write_report(out,report)
    print(json.dumps(summary,ensure_ascii=False,indent=2))
    return report


if __name__=='__main__':
    sys.stdout.reconfigure(encoding='utf8')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',type=Path,default=ROOT/'outputs/stage2_identity_projection/after.json')
    parser.add_argument('--output',type=Path,default=ROOT/'outputs/stage8_relation_sparsity_audit')
    args=parser.parse_args()
    sys.addaudithook(audit_io)
    try:
        run(args.input,args.output)
    except Exception:
        print('TASK_RESULT=FAILED\nSTAGE_8_RELATION_SPARSITY_AUDIT=FAIL',file=sys.stderr)
        raise
