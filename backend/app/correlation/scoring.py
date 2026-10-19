"""Seven-component member-pair scoring with unrounded selection and guards."""

from collections import defaultdict
from dataclasses import dataclass
import math

from app.config import _condition_matches, resolve_mapping
from app.dedup.grouping import DuplicateScorer
from app.models import AlertRelationType, ScoreBreakdown, SourceIndependence
from app.utils.stable_id import canonical_json
from .conflicts import pair_conflicts
from .reasons import bound_fields, make_reason


@dataclass(frozen=True)
class VerifiedRelation:
    relation_type: str
    source_alert_id: str
    target_alert_id: str
    source_entity_id: str
    target_entity_id: str
    raw_pointers: tuple[dict, ...]

    def json_data(self):
        return {**self.__dict__, "raw_pointers": list(self.raw_pointers)}


@dataclass
class PairScore:
    source_member_id: str
    target_member_id: str
    score: float
    values: dict
    contributions: dict
    raw_total: float
    source_independence: str
    reasons: list
    entity_ids: list[str]
    relations: list[VerifiedRelation]
    rejection_codes: list[str]
    diagnostics: dict

    @property
    def valid(self):
        return not self.rejection_codes


class CorrelationScorer:
    def __init__(self, index, config, source_settings, config_hash=None):
        self.index, self.config = index, config
        self.algorithm = config.algorithm
        self.config_hash = config_hash or config.config_hash
        self.settings = source_settings
        if set(index.alerts[a].source_namespace for a in index.alerts) - source_settings.keys():
            raise ValueError("missing_source_settings")
        self.duplicate = DuplicateScorer(index.alerts.values(), config, source_settings)
        from app.services.capacity import BoundedCache, execution_state
        if execution_state() is not None:
            self.duplicate.cache = BoundedCache()
        self.half_lives = {(r.from_category, r.to_category): r for r in self.algorithm.time.transition_half_lives}
        self.behaviors = {(r.from_category, r.to_category): r.score for r in self.algorithm.behavior.transitions}
        self.independence_mappings = config.mapping_files["source.independence_mapping_files"]
        self.has_independence_mappings = any(m.rules for m in self.independence_mappings)
        self.source_facets = {}
        self.origins = defaultdict(set)
        self.sensors = defaultdict(set)
        self.origin_namespaces = defaultdict(set)
        for aid, a in index.alerts.items():
            if self.origin_key(a) is not None:
                self.origins[self.origin_key(a)].add(aid)
            if a.sensor is not None:
                self.sensors[a.sensor].add(aid)
            if a.origin_namespace is not None:
                self.origin_namespaces[a.origin_namespace].add(aid)
        self.instances = set()
        for eid, e in index.entities.items():
            if e.type.value == "PROCESS":
                for aid in e.alert_ids:
                    a = index.alerts[aid]
                    if any(a.host is not None and getattr(a, role).pid is not None and getattr(a, role).start_time is not None
                           for role in index.roles[aid][eid].intersection({"process", "parent_process"})):
                        self.instances.add(eid)
                        break
        self.evidence_evaluator = None
        if self.algorithm.version == "v2":
            from .evidence import EvidenceEvaluator
            self.evidence_evaluator = EvidenceEvaluator(self)
        elif self.algorithm.version == "v3":
            from .evidence_v3 import EvidenceV3Evaluator
            self.evidence_evaluator = EvidenceV3Evaluator(self)
        elif self.algorithm.version == 'v4':
            from .evidence_v4 import EvidenceV4Evaluator
            self.evidence_evaluator = EvidenceV4Evaluator(self)

    def is_instance(self, eid):
        return eid in self.instances

    def entity_features(self, a, b):
        idx, cfg = self.index, self.algorithm.entity
        shared = sorted(set(a.entity_ids).intersection(b.entity_ids))
        by_type, selected = defaultdict(list), []
        for eid in shared:
            e = idx.entities[eid]
            roles_a, roles_b = idx.roles[a.alert_id][eid], idx.roles[b.alert_id][eid]
            role = max(cfg.role_factors.same_role if x == y else cfg.role_factors.src_dst_bridge
                       if {x, y} == {"src_ip", "dst_ip"} else cfg.role_factors.other_role for x in roles_a for y in roles_b)
            descriptor = cfg.process_descriptor_factor if e.type.value == "PROCESS" and not self.is_instance(eid) else 1.0
            rarity = idx.rarity(eid, cfg)
            x = min(1.0, max(0.0, cfg.weights[e.type.value] * rarity * role * descriptor))
            by_type[e.type.value].append({"entity_id": eid, "type": e.type.value, "x": x, "rarity": rarity,
                                        "role_factor": role, "descriptor_factor": descriptor,
                                        "roles": sorted(roles_a | roles_b)})
        for kind in sorted(by_type):
            selected.extend(sorted(by_type[kind], key=lambda f: (-f["x"], f["entity_id"]))[:cfg.max_contributors_per_type])
        value = 1 - math.prod(1 - f["x"] for f in selected) if selected else 0.0
        return value, shared, selected

    def verify_relations(self, a, b):
        idx = self.index
        found, refused = [], []
        def add(kind, src, dst, se, te, pointers):
            key = (kind, src.alert_id, dst.alert_id, se, te, canonical_json(pointers))
            found.append((key, VerifiedRelation(kind, src.alert_id, dst.alert_id, se, te, tuple(pointers))))
        # Existing full process-instance identities provide a cross-alert
        # parent→child proof, even when only the child has a local AlertRelation.
        for src, dst in ((a, b), (b, a)):
            for eid in sorted(set(src.entity_ids).intersection(dst.entity_ids)):
                if ("process" in idx.roles[src.alert_id][eid] and "parent_process" in idx.roles[dst.alert_id][eid]
                        and self.is_instance(eid) and src.host == dst.host):
                    child_ids = [i for i, roles in idx.roles[dst.alert_id].items() if "process" in roles and self.is_instance(i)]
                    for child in sorted(child_ids):
                        p, c = src.process, dst.process
                        if p.pid != c.pid and p.start_time <= c.start_time:
                            pointers = bound_fields(src, ["process", "host"], "src") + bound_fields(dst, ["parent_process", "process", "host"], "dst")
                            add("parent_child_process", src, dst, eid, child, pointers)
        # Other propagation types must already be attested by the Task 02
        # structured relation contract. Scoring never extracts new raw fields.
        # Pointer existence alone is insufficient: enforce type-specific facts,
        # scopes, role endpoints and both sides of the actual member pair.
        for owner in (a, b):
            for relation in owner.relations:
                kind, se, te = relation.relation_type.value, relation.source_entity_id, relation.target_entity_id
                if kind == "parent_child_process":
                    continue
                pointers = [p.model_dump(mode="json") for p in relation.raw_pointers]
                if {p["alert_id"] for p in pointers} - {a.alert_id, b.alert_id}:
                    refused.append({"relation_type": kind, "rule_id": "relation_outside_support_pair"})
                    continue
                accepted = False
                for src, dst in ((a, b), (b, a)):
                    if se not in src.entity_ids or te not in dst.entity_ids:
                        continue
                    if not {src.alert_id, dst.alert_id} <= {p["alert_id"] for p in pointers}:
                        continue
                    es, et = idx.entities[se], idx.entities[te]
                    shared = set(src.entity_ids).intersection(dst.entity_ids)
                    context = {idx.entities[i].type.value for i in shared}
                    if kind == "target_to_process":
                        accepted = (es.type.value == "HOST" and et.type.value == "PROCESS" and self.is_instance(te)
                                    and src.host is not None and src.host == dst.host
                                    and "HOST" in context and src.category.value in {"web_attack", "initial_access"}
                                    and dst.category.value in {"process_execution", "command_execution"})
                        # The upstream attestation must include a substantive
                        # connecting field, beyond canonical endpoint/context.
                        endpoint_pointers = {p["pointer"] for alert in (src, dst) for p in bound_fields(alert, ["host", "process", "timestamp", "session", "category"])}
                        accepted = accepted and any(p["pointer"] not in endpoint_pointers and p["pointer"] != "" for p in pointers)
                    elif kind == "account_host_pivot":
                        accepted = (bool(context.intersection({"ACCOUNT", "SESSION"})) and src.host is not None
                                    and dst.host is not None and src.host != dst.host and es.type.value in {"HOST", "ACCOUNT", "SESSION"}
                                    and et.type.value in {"HOST", "ACCOUNT", "SESSION"})
                    elif kind == "network_pivot":
                        accepted = (src.dst_ip is not None and src.dst_ip == dst.src_ip
                                    and es.type.value == et.type.value == "IP" and es.scope == et.scope
                                    and "dst_ip" in idx.roles[src.alert_id].get(se, set())
                                    and "src_ip" in idx.roles[dst.alert_id].get(te, set()))
                    elif kind == "session_continuity":
                        accepted = (es.type.value == et.type.value == "SESSION" and se == te
                                    and src.session is not None and src.session == dst.session)
                    # Upstream relation src/dst pointer roles carry the attested
                    # operation order; do not reverse it based on timestamp.
                    accepted = accepted and any(p["alert_id"] == src.alert_id and p["side"] == "src" for p in pointers)
                    accepted = accepted and any(p["alert_id"] == dst.alert_id and p["side"] == "dst" for p in pointers)
                    if accepted:
                        add(kind, src, dst, se, te, pointers)
                        break
                if not accepted:
                    refused.append({"relation_type": kind, "rule_id": "relation_field_gate_failed"})
        return [r for _, r in sorted(dict(found).items())], refused

    def behavior_value(self, src, dst):
        x, y, cfg = src.category.value, dst.category.value, self.algorithm.behavior
        if "unknown" in (x, y):
            return cfg.unknown_category
        if x == y:
            return cfg.same_category
        return self.behaviors.get((x, y), cfg.unlisted_transition)

    def ordered_pairs(self, a, b):
        if a.timestamp == b.timestamp:
            return [(a, b), (b, a)]
        return [(a, b)] if a.timestamp < b.timestamp else [(b, a)]

    @staticmethod
    def origin_key(alert):
        return (alert.origin_namespace, alert.origin_record_id) if alert.origin_namespace is not None else (
            (alert.source_namespace, alert.source_record_id) if alert.source_record_id is not None else None)

    def independence(self, a, b):
        same = self.origin_key(a) is not None and self.origin_key(a) == self.origin_key(b)
        ids, matches = [], []
        for left, right in ((a, b), (b, a)):
            context = {side + "." + name: getattr(alert, name).value if name == "source_type" else getattr(alert, name)
                       for side, alert in (("left", left), ("right", right))
                       for name in ("source_type", "source_namespace", "sensor", "origin_namespace")}
            for mapping in self.independence_mappings:
                if mapping.source_type not in (left.source_type.value, right.source_type.value):
                    continue
                resolution = resolve_mapping(mapping, context)
                if resolution.output == "confirmed_independent":
                    ids.extend(resolution.matched_rule_ids)
                    matches.append({"mapping_digest": resolution.mapping_digest, "rule_ids": resolution.matched_rule_ids})
        pointers = bound_fields(a, ["origin_namespace", "origin_record_id", "source_record_id"]) + bound_fields(b, ["origin_namespace", "origin_record_id", "source_record_id"]) if same else []
        state = "confirmed_same_origin" if same else "confirmed_independent" if ids else "unknown"
        return state, sorted(set(ids)), pointers, matches

    @staticmethod
    def sides(alert):
        host = alert.category.value in {"process_execution", "command_execution"} and (alert.process is not None or alert.command is not None)
        network = alert.category.value in {"web_attack", "initial_access", "command_and_control"} and (alert.src_ip is not None or alert.dst_ip is not None or alert.url is not None)
        return host, network

    def complement(self, a, b, shared, relations):
        state, ids, pointers, matches = self.independence(a, b)
        cfg = self.algorithm.source
        bridge = any(self.index.entities[e].type.value in {"HOST", "SESSION"} for e in shared) or bool(relations)
        ah, an = self.sides(a)
        bh, bn = self.sides(b)
        sides = (ah and bn) or (bh and an)
        if state != "confirmed_independent":
            return 0.0, state, "source." + state, ids, pointers, matches
        if a.sensor is not None and a.sensor == b.sensor:
            return cfg.same_sensor_score, state, "source.same_sensor_score", ids, pointers, matches
        if not bridge or not sides:
            return 0.0, state, "source.context_or_side_gate", ids, pointers, matches
        products = {a.source_type.value, b.source_type.value}
        context_types = {self.index.entities[e].type.value for e in shared}
        for rule in cfg.complement_rules:
            if products == set(rule.source_types):
                web_pair = products in ({"waf", "edr"}, {"waf", "wazuh"})
                if web_pair and ("web_attack" not in {a.category.value, b.category.value} or "HOST" not in context_types):
                    return 0.0, state, "source.complement_condition_failed", ids, pointers, matches
                if products == {"wazuh", "aminer"} and not context_types.intersection({"HOST", "SESSION"}):
                    return 0.0, state, "source.complement_condition_failed", ids, pointers, matches
                if products in ({"suricata", "edr"}, {"ids", "edr"}) and "HOST" not in context_types and not relations:
                    return 0.0, state, "source.complement_condition_failed", ids, pointers, matches
                return rule.score, state, "source.complement_rules:" + "+".join(sorted(products)), ids, pointers, matches
        value = cfg.same_type_independent_score if a.source_type == b.source_type else cfg.different_type_confirmed_independent_unlisted_score
        return value, state, "source.same_type_independent_score" if a.source_type == b.source_type else "source.different_type_confirmed_independent_unlisted_score", ids, pointers, matches

    def source_postings(self, aid, eid):
        """Compile bounded mapping predicates into reusable scoped postings.

        Mapping v1 compares each side to constants, so no all-facet/all-alert pair
        join is necessary. Both field/side gates and origin/sensor exclusions are
        applied before candidate budgets. Each compiled posting is built once.
        """
        a = self.index.alerts[aid]
        host_side, network_side = self.sides(a)
        if not host_side and not network_side:
            return []
        excluded = self.origins.get(self.origin_key(a), set()) | self.sensors.get(a.sensor, set())
        # Preserve the frozen mapping loader's same-origin-namespace invariant.
        if a.origin_namespace is not None:
            excluded |= self.origin_namespaces[a.origin_namespace]
        result = []
        for file_number, mapping in enumerate(self.independence_mappings):
            for rule in mapping.rules:
                for own_side, other_side in (("left", "right"), ("right", "left")):
                    own_conditions = [p for p in rule.match.all if p.field.startswith(own_side + ".")]
                    other_conditions = [p for p in rule.match.all if p.field.startswith(other_side + ".")]
                    def matches(alert, conditions):
                        return all(_condition_matches(p, getattr(alert, p.field.split(".", 1)[1]).value
                                   if p.field.endswith("source_type") else getattr(alert, p.field.split(".", 1)[1])) for p in conditions)
                    if not matches(a, own_conditions):
                        continue
                    key = (eid, file_number, rule.id, own_side, a.category.value, a.source_type.value, host_side, network_side)
                    if key not in self.source_facets:
                        members = []
                        for i in self.index.entities[eid].alert_ids:
                            b = self.index.alerts[i]
                            bh, bn = self.sides(b)
                            if mapping.source_type not in {a.source_type.value, b.source_type.value} or not matches(b, other_conditions):
                                continue
                            if not ((host_side and bn) or (network_side and bh)):
                                continue
                            products = {a.source_type.value, b.source_type.value}
                            if products in ({"waf", "edr"}, {"waf", "wazuh"}) and (
                                "web_attack" not in {a.category.value, b.category.value} or self.index.entities[eid].type.value != "HOST"):
                                continue
                            if products in ({"suricata", "edr"}, {"ids", "edr"}) and self.index.entities[eid].type.value != "HOST":
                                continue
                            members.append(i)
                        self.source_facets[key] = self.index.postings(members)
                    if self.source_facets[key]:
                        result.append((self.source_facets[key], excluded))
        return result

    def score_pair(self, left, right):
        a, b = self.index.alerts[left], self.index.alerts[right]
        pair = [left, right]
        context = {"alerts": self.index.alerts}
        gap = abs(self.index.times[left] - self.index.times[right]) / 1000000
        ordered = self.ordered_pairs(a, b)
        half_candidates = [self.half_lives.get((x.category.value, y.category.value)) for x, y in ordered]
        half = max((r.half_life_seconds if r else self.algorithm.time.default_half_life_seconds for r in half_candidates))
        windows = [r.window_seconds for r in half_candidates if r is not None]
        time = math.exp(-math.log(2) * gap / half)
        entity, shared, features = self.entity_features(a, b)
        relations, refused = self.verify_relations(a, b)
        relation = max((self.algorithm.relation.scores[r.relation_type] for r in relations), default=0.0)
        behavior_order = min(ordered, key=lambda xy: (-self.behavior_value(*xy), xy[0].alert_id, xy[1].alert_id))
        behavior = self.behavior_value(*behavior_order)
        source, state, source_rule, independence_ids, pointers, matches = self.complement(a, b, shared, relations)
        conflicts = pair_conflicts(a, b, self.index, self.algorithm, self.settings, relations, shared, windows)
        duplicate = self.duplicate.score(left, right)
        if (self.algorithm.version in {'v3', 'v4'} and self.algorithm.duplicate.observation.event_pointers
                and any(rule == 'different_target_without_bridge' for rule, _ in conflicts['soft'])
                and not duplicate.get('observation_identity', {}).get('equivalent')):
            _, flow_strength, flow_ids, _ = self.evidence_evaluator.network(a, b)
            if (flow_strength >= self.algorithm.score.evidence_v3.primary_minimum_reliability
                    and any(not self.evidence_evaluator.hot(e) for e in flow_ids)):
                # A verified flow is correlation context. It never attests an
                # AlertRelation or bypasses downstream Target Set guards.
                conflicts['soft'] = [(rule, value) for rule, value in conflicts['soft'] if rule != 'different_target_without_bridge']
                conflicts['penalty'] = max((value for _, value in conflicts['soft']), default=0.)
                conflicts['correlation_flow_context_bridge'] = True
        # This cache belongs to Task 02's scorer; correlation has no repeated
        # pair need and must not retain a full-dataset cache in addition to data.
        self.duplicate.cache.pop(tuple(sorted(pair)), None)
        floor = self.algorithm.duplicate.suspected_floor
        dup_penalty = max(0.0, min(1.0, (duplicate["score"] - floor) / (1 - floor)))
        values = {"time": time, "entity": entity, "relation": relation, "behavior": behavior, "source": source,
                  "conflict": conflicts["penalty"], "duplicate": dup_penalty}
        weights = self.algorithm.score.weights
        contributions = {k: getattr(weights, k) * v * (-1 if k in {"conflict", "duplicate"} else 1) for k, v in values.items()}
        raw = sum(contributions.values())
        score = max(0.0, min(1.0, raw))
        reasons = [make_reason("time_gap", pair, {"gap_seconds": gap, "half_life_seconds": half})]
        for f in features:
            reasons.append(make_reason("shared_entity", pair, {"entity_type": f["type"], "roles": f["roles"],
                                  "rarity": round(f["rarity"], 6), "contribution": round(f["x"], 6)}, [f["entity_id"]]))
        for r in relations:
            reasons.append(make_reason("explicit_relation", pair, {"relation_type": r.relation_type, "raw_pointers": list(r.raw_pointers)},
                                       [r.source_entity_id, r.target_entity_id], context))
        reasons.append(make_reason("behavior_transition", pair, {"from_category": behavior_order[0].category.value,
                                  "to_category": behavior_order[1].category.value, "compatibility": round(behavior, 6)}))
        reasons.append(make_reason("source_complement", pair, {"source_types": sorted({a.source_type.value, b.source_type.value}),
                                  "sensor_names": sorted({v for v in (a.sensor, b.sensor) if v is not None}), "rule_id": source_rule,
                                  "source_independence": state, "raw_pointers": pointers, "independence_rule_ids": independence_ids}, context=context))
        for rule, penalty in conflicts["soft"]:
            reasons.append(make_reason("conflict", pair, {"rule_id": "conflict.strengths:" + rule, "penalty": round(penalty, 6)}))
        reasons.append(make_reason("duplicate", pair, {"rule_id": "duplicate.feature_weights", "similarity": round(duplicate["score"], 6)}))
        entity_ids = sorted({f["entity_id"] for f in features} | {eid for r in relations for eid in (r.source_entity_id, r.target_entity_id)})
        rejections = list(conflicts["hard"])
        if not shared and not relations:
            rejections.append("missing_non_time_support")
        # Candidate generation enforces channel windows. Other channels may
        # admit an over-behavior-window pair; it receives the frozen soft penalty.
        diagnostics = {"gap_seconds": gap, "half_life_seconds": half, "entity_features": features,
                       "shared_entity_ids": shared, "relations": [r.json_data() for r in relations], "refused_relations": refused,
                       "source_rule": source_rule, "source_mapping_matches": matches, "conflicts": conflicts,
                       "duplicate_features": duplicate, "behavior_order": [behavior_order[0].alert_id, behavior_order[1].alert_id]}
        if self.evidence_evaluator is not None:
            raw, score, audit = self.evidence_evaluator.evaluate(a, b, values, features, relations, refused, state, conflicts["hard"])
            diagnostics["evidence_v2"] = audit
            if self.algorithm.version in {"v3", "v4"}:
                entity_ids = sorted(set(entity_ids) | {eid for d in audit["dimensions"]
                    if d["state"] == "AVAILABLE_MATCH" for eid in d["entity_ids"]})
            if not audit["evidence_gate_passed"]:
                rejections.append("insufficient_evidence:" + audit["gate_reason"])
        if self.algorithm.implementation_version in {'v5-formula-f3-v1','v5-evidence-semantics-v1'}:
            from .evidence_v5 import evaluate
            v5 = evaluate(self,a,b,audit,values,relations,conflicts)
            diagnostics['evidence_v5'] = v5
            raw,score = v5['raw_total'],v5['final_score']
            rejections = [r for r in rejections if not r.startswith('insufficient_evidence:')]
            if not v5['gate']['passed']:
                rejections.append('v5_semantic_guard')
        return PairScore(left, right, score, values, contributions, raw, state,
                         sorted({r.reason_id: r for r in reasons}.values(), key=lambda r: r.reason_id), entity_ids, relations, sorted(rejections), diagnostics)

    def breakdown(self, pair):
        if 'evidence_v5' in pair.diagnostics:
            from app.models.correlation_v5 import ScoreBreakdownV5
            from .formula_v5 import identity
            algorithm_version,implementation_version=identity(pair.diagnostics['evidence_v5']['policy'])
            return ScoreBreakdownV5.model_validate(dict(**{**pair.diagnostics['evidence_v5'],
                'final_score':round(pair.score,6),'raw_total':round(pair.raw_total,6)},
                schema_version='5.1' if implementation_version=='v5-evidence-semantics-v1' else '5.0',
                algorithm_version=algorithm_version,implementation_version=implementation_version,
                config_hash=self.config_hash,mapping_digest=self.config.mapping_digest,
                threshold=self.algorithm.score.correlation_threshold,
                threshold_passed=pair.score>=self.algorithm.score.correlation_threshold,
                source_independence=pair.source_independence,
                legacy_audit=dict(values=pair.values,weights=self.algorithm.score.weights.model_dump(),contributions=pair.contributions)))
        data = {k + ("_penalty" if k in {"conflict", "duplicate"} else "_score"): round(v, 6) for k, v in pair.values.items()}
        data.update(source_independence=pair.source_independence, weights=self.algorithm.score.weights.model_dump(),
                    contributions={k: round(v, 6) for k, v in pair.contributions.items()}, raw_total=round(pair.raw_total, 6),
                    final_score=round(pair.score, 6), config_hash=self.config_hash)
        if "evidence_v2" in pair.diagnostics:
            data["evidence_v2"] = pair.diagnostics["evidence_v2"]
        return ScoreBreakdown.model_validate(data)
