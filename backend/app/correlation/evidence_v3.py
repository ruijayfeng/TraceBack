"""Evidence independence, primary support and endpoint validity for v3 only."""

from collections import defaultdict
import math
from urllib.parse import urlsplit

from .evidence import EvidenceEvaluator, FAMILIES
from .reasons import bound_fields


ENTITY_FAMILY = {'HOST': 'HOST_CONTEXT', 'ACCOUNT': 'ACCOUNT_CONTEXT', 'PROCESS': 'PROCESS_CONTEXT',
    'SESSION': 'ENTITY_IDENTITY', 'IP': 'ENTITY_IDENTITY', 'DOMAIN': 'RESOURCE_CONTEXT',
    'URL': 'RESOURCE_CONTEXT', 'FILE': 'RESOURCE_CONTEXT', 'COMMAND': 'RESOURCE_CONTEXT'}


class EvidenceV3Evaluator(EvidenceEvaluator):
    def __init__(self, scorer):
        super().__init__(scorer)
        self.repair = scorer.algorithm.score.evidence_v3

    def reliability(self, feature):
        eid = feature['entity_id']
        rarity = self.rarity(eid)
        value = self.repair.reliability_floor + (1-self.repair.reliability_floor)*rarity
        return value * feature['role_factor'] * feature['descriptor_factor']

    def rarity(self, eid):
        idx = self.scorer.index
        population = max(idx.N, self.repair.frequency_population_floor)
        return max(self.scorer.algorithm.entity.rarity_floor,
            math.log((population+1)/(idx.df[eid]+1))/math.log(population+1))

    def network(self, a, b):
        idx = self.scorer.index
        if any(x.src_ip is not None and x.src_ip == x.dst_ip for x in (a, b)):
            return False, 0., [], 'local_host_observation'
        if not all(x.src_ip is not None and x.dst_ip is not None for x in (a, b)):
            return False, 0., [], 'network_fields_unavailable'
        src, dst = sorted((a, b), key=lambda x: (idx.times[x.alert_id], x.alert_id))
        if idx.times[src.alert_id] >= idx.times[dst.alert_id]:
            return True, 0., [], 'timestamp_order_unproven'
        left = {e for e in src.entity_ids if 'dst_ip' in idx.roles[src.alert_id][e]}
        right = {e for e in dst.entity_ids if 'src_ip' in idx.roles[dst.alert_id][e]}
        bridge = sorted(left & right)
        if not bridge:
            return True, 0., [], 'no_scoped_endpoint_bridge'
        observations = self.scorer.duplicate.observation.identities
        first, second = observations[src.alert_id], observations[dst.alert_id]
        complete_flows = (first.event_fingerprint and second.event_fingerprint
            and first.protocol == second.protocol and first.event_fingerprint != second.event_fingerprint)
        if self.scorer.algorithm.duplicate.observation.event_pointers and not complete_flows:
            return True, 0., [], 'endpoint_bridge_without_independent_flow_context'
        ports = src.dst_port is not None and src.dst_port == dst.src_port
        transition = (src.category.value != dst.category.value and src.category.value != 'unknown'
            and dst.category.value != 'unknown' and self.scorer.behavior_value(src, dst) >= self.repair.network_behavior_minimum)
        if not (ports or transition):
            return True, 0., [], 'endpoint_equality_without_direction_context'
        quality = max(self.repair.reliability_floor + (1-self.repair.reliability_floor)*self.rarity(e) for e in bridge)
        prefix = 'flow_confirmed_with_' if self.scorer.algorithm.duplicate.observation.event_pointers else 'ordered_cross_entity_flow_with_'
        return True, quality*self.repair.network_strength, bridge, prefix + ('port_context' if ports else 'behavior_context')

    def specific_resource(self, feature, a, b):
        if self.repair.weak_resource_descriptor_factor == 1.0:
            return True  # Historical v3 recipe, prior to the descriptor repair.
        kind = feature['type']
        if kind == 'URL':
            resource = urlsplit(self.scorer.index.entities[feature['entity_id']].value)
            target = bool(resource.hostname) or bool(a.host and b.host or a.domain and b.domain)
            return target and resource.path not in ('', '/', '.')
        if kind in ('FILE', 'COMMAND'):
            return bool(a.host and b.host) and self.scorer.index.entities[feature['entity_id']].value not in ('/', '.', '\\')
        return True

    def detector_different(self, a, b):
        return any(getattr(a, f) is not None and getattr(b, f) is not None and getattr(a, f) != getattr(b, f)
            for f in ('rule_id', 'signature', 'alert_type')) if a.source_namespace == b.source_namespace else False

    def metadata_support(self, metadata):
        return (any(d['state'].startswith('AVAILABLE') for d in metadata),
                max((d['strength'] for d in metadata), default=0.) * self.repair.metadata_cap)

    def evaluate(self, a, b, values, features, relations, refused, source_state, hard):
        a, b = sorted((a, b), key=lambda x: x.alert_id)
        _, _, base = super().evaluate(a, b, values, features, relations, refused, source_state, hard)
        scorer, cfg, idx = self.scorer, self.repair, self.scorer.index
        dimensions = {d['dimension']: d for d in base['dimensions']}
        facts, reliability, suppressed = [], [], []
        def refs(fields):
            # Correlation is undirected; raw member lexical ordering need not
            # equal representative endpoint ordering. Only attested relation
            # pointers below carry directional src/dst roles.
            return bound_fields(a, fields, 'shared') + bound_fields(b, fields, 'shared')
        def fact(family, key, dim, primary=False, entity_ids=(), evidence_refs=()):
            if dimensions[dim]['strength'] > 0:
                entry = dict(family=family, fact_key=key, dimension=dim,
                    role='primary' if primary else 'supporting', strength=dimensions[dim]['strength'],
                    entity_ids=sorted(set(entity_ids)), evidence_refs=list(evidence_refs))
                if scorer.algorithm.duplicate.observation.event_pointers:
                    entry.update(source_alert_ids=sorted([a.alert_id,b.alert_id]),
                        observation_ids=sorted({scorer.duplicate.observation.identities[x.alert_id].observation_id for x in (a,b)}))
                facts.append(entry)
        def set_dim(name, observable, strength, ids=(), na=False):
            d = dimensions[name]
            d.update(state='NOT_APPLICABLE' if na else 'UNAVAILABLE' if not observable else
                'AVAILABLE_MATCH' if strength > 0 else 'AVAILABLE_MISMATCH', strength=strength, entity_ids=sorted(set(ids)))
        network_observable, network_strength, network_ids, network_diagnostic = self.network(a, b)
        relation_ids = {e for r in relations for e in (r.source_entity_id, r.target_entity_id)}
        if scorer.algorithm.duplicate.observation.event_pointers and set(network_ids) & relation_ids:
            network_strength, network_ids = 0., []
            network_diagnostic = 'attested_relation_consumes_endpoint_bridge'
        set_dim('topology.network_continuity', network_observable, network_strength, network_ids,
                na=network_diagnostic in ('local_host_observation', 'attested_relation_consumes_endpoint_bridge'))
        consumed = set(network_ids) | {e for r in relations for e in (r.source_entity_id, r.target_entity_id)}
        detector_different = self.detector_different(a, b)
        behavior_different = a.category.value != 'unknown' and b.category.value != 'unknown' and a.category != b.category
        selected = defaultdict(list)
        for f in features:
            if not self.specific_resource(f, a, b):
                f = {**f, 'descriptor_factor':f['descriptor_factor']*cfg.weak_resource_descriptor_factor}
            strength = self.reliability(f)
            reliability.append(dict(entity_id=f['entity_id'], frequency=idx.df[f['entity_id']], population=idx.N,
                rarity=self.rarity(f['entity_id']), reliability=strength,
                role_factor=f['role_factor'], descriptor_factor=f['descriptor_factor'], hot=self.hot(f['entity_id'])))
            if f['entity_id'] not in consumed:
                selected[f['type']].append((strength, f))
        for kind in sorted(scorer.algorithm.entity.weights):
            name = 'entity.' + kind
            observable = bool(self.by_type[a.alert_id].get(kind)) and bool(self.by_type[b.alert_id].get(kind))
            none = not self.by_type[a.alert_id].get(kind) and not self.by_type[b.alert_id].get(kind)
            entries = selected[kind]
            best = min(entries, key=lambda item: (-item[0], item[1]['entity_id'])) if entries else None
            excluded = any(f['type'] == kind and f['entity_id'] in consumed for f in features)
            set_dim(name, observable, best[0] if best else 0., [best[1]['entity_id']] if best else (), na=none or excluded and not best)
            if excluded:
                suppressed.append(name)
            if best:
                strength, f = best
                eid = f['entity_id']
                primary = strength >= cfg.primary_minimum_reliability and not self.hot(eid)
                if kind in ('HOST', 'ACCOUNT'):
                    primary &= detector_different or behavior_different
                elif kind == 'PROCESS':
                    primary &= scorer.is_instance(eid)
                elif kind == 'SESSION':
                    primary &= (self.rarity(eid) >= self.cfg.gate.strong_identifier_minimum_rarity
                        and scorer.settings[a.source_namespace].session_scope is not None
                        and scorer.settings[b.source_namespace].session_scope is not None)
                elif kind in ('URL', 'FILE', 'COMMAND'):
                    primary &= self.rarity(eid) >= self.cfg.gate.specific_minimum_rarity and self.specific_resource(f, a, b)
                else:
                    primary = False
                fields = sorted(idx.roles[a.alert_id][eid] | idx.roles[b.alert_id][eid])
                fact(ENTITY_FAMILY[kind], 'entity:' + eid, name, bool(primary), [eid], refs(fields))
        metadata = [d for d in base['dimensions'] if d['family'] == 'behavior']
        observable, metadata_strength = self.metadata_support(metadata)
        for d in metadata:
            dimensions.pop(d['dimension'])
        dimensions['metadata.detector_identity'] = dict(dimension='metadata.detector_identity', family='behavior',
            state='AVAILABLE_MATCH' if metadata_strength > 0 else 'AVAILABLE_MISMATCH' if observable else 'UNAVAILABLE',
            weight=1., strength=metadata_strength, entity_ids=[])
        fact('RULE_METADATA', 'detector_metadata', 'metadata.detector_identity', evidence_refs=refs(['category', 'rule_id', 'signature', 'alert_type']))
        fact('TEMPORAL', 'timestamp_distance', 'time.distance', evidence_refs=refs(['timestamp']))
        if network_strength:
            primary = network_strength >= cfg.primary_minimum_reliability and any(not self.hot(e) for e in network_ids)
            fact('NETWORK_FLOW', 'network:' + ':'.join(network_ids), 'topology.network_continuity', primary,
                network_ids, refs(['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'category']))
        if relations:
            fact('BEHAVIOR_SEMANTIC', 'attested_relation', 'topology.attested_relation', True,
                [e for r in relations for e in (r.source_entity_id, r.target_entity_id)], [p for r in relations for p in r.raw_pointers])
        fact('SOURCE_CONTEXT', 'independent_complement', 'context.independent_complement', evidence_refs=refs(['sensor', 'origin_namespace']))
        ordered = [dimensions[n] for n in sorted(dimensions)]
        strengths, available = {}, []
        for family in FAMILIES:
            ds = [d for d in ordered if d['family'] == family and d['state'].startswith('AVAILABLE')]
            den = math.fsum(d['weight'] for d in ds)
            strengths[family] = max((d['strength'] for d in ds), default=0.) if family == 'relation' else math.fsum(d['weight']*d['strength'] for d in ds)/den if den else 0.
            if den:
                available.append(family)
        weights = base['family_weights']
        aw = math.fsum(weights[k] for k in available)
        mw = math.fsum(weights[k]*strengths[k] for k in available)
        tw = math.fsum(weights.values())
        quality, mass = mw/aw if aw else 0., mw/tw
        observation = scorer.duplicate.observation.compare(a, b)
        # Conservative dedupe windows/field conflicts may leave one attested
        # observation in two groups. That does not create two independent facts.
        duplicate_risk = observation['equivalent'] or bool(scorer.algorithm.duplicate.observation.event_pointers
            and len(observation['observation_ids']) < 2)
        primary = sorted(f['fact_key'] for f in facts if f['role'] == 'primary')
        supporting = sorted(f['fact_key'] for f in facts if f['role'] == 'supporting')
        dominated = not primary and metadata_strength > 0
        passed = bool(primary) and not duplicate_risk and mass >= self.cfg.gate.minimum_mass
        reason = ('duplicate_observation_only' if duplicate_risk else 'metadata_dominated_candidate' if dominated else
            'insufficient_primary_evidence' if not primary else 'minimum_evidence_mass' if mass < self.cfg.gate.minimum_mass else 'independent_primary_evidence')
        raw = self.cfg.quality_factor*quality + self.cfg.mass_factor*mass - scorer.algorithm.score.weights.conflict*values['conflict'] - scorer.algorithm.score.weights.duplicate*values['duplicate']
        score = min(1., max(0., raw))
        threshold_passed = score >= scorer.algorithm.score.correlation_threshold
        decision = 'REJECT_GUARD' if hard else 'REJECT_INSUFFICIENT_EVIDENCE' if not passed else 'REJECT_LOW_SCORE' if not threshold_passed else 'ACCEPT'
        base.update(version='v3', dimensions=ordered, family_strengths=strengths, available_weight=aw, matched_weight=mw,
            normalized_quality=quality, evidence_mass=mass, strong_evidence_count=len(primary), supporting_evidence_count=len(supporting),
            evidence_gate_passed=passed, gate_reason=reason, threshold_passed=threshold_passed, decision=decision,
            evidence=sorted(facts, key=lambda f: f['fact_key']), evidence_families=sorted({f['family'] for f in facts}),
            primary_evidence=primary, supporting_evidence=supporting,
            applicable_evidence_families=sorted({ENTITY_FAMILY[d['dimension'][7:]] if d['dimension'].startswith('entity.') else
                'TEMPORAL' if d['family']=='time' else 'RULE_METADATA' if d['family']=='behavior' else
                'SOURCE_CONTEXT' if d['family']=='source' else 'NETWORK_FLOW' if d['dimension']=='topology.network_continuity' else 'BEHAVIOR_SEMANTIC'
                for d in ordered if d['state'].startswith('AVAILABLE')}),
            entity_reliability=sorted(reliability, key=lambda r: r['entity_id']), duplicate_observation_risk=duplicate_risk,
            reliability_floor=cfg.reliability_floor, frequency_population_floor=cfg.frequency_population_floor,
            rarity_floor=scorer.algorithm.entity.rarity_floor,
            metadata_dominated=dominated, network_continuity_valid=bool(network_strength), network_diagnostic=network_diagnostic,
            relation_support=sorted({r.relation_type for r in relations}), suppressed_dimensions=sorted(suppressed))
        for name, st in (('matched_evidence','AVAILABLE_MATCH'),('mismatched_evidence','AVAILABLE_MISMATCH'),
                         ('unavailable_evidence','UNAVAILABLE'),('not_applicable_evidence','NOT_APPLICABLE')):
            base[name] = [d['dimension'] for d in ordered if d['state'] == st]
        base['available_evidence'] = [d['dimension'] for d in ordered if d['state'].startswith('AVAILABLE')]
        return raw, score, base
