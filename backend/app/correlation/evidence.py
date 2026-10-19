"""Availability, quality, mass and sufficiency; never creates causal relations."""

from collections import defaultdict
import math


FAMILIES = ("time", "entity", "relation", "behavior", "source")


class EvidenceEvaluator:
    def __init__(self, scorer):
        self.scorer = scorer
        self.cfg = scorer.algorithm.score.evidence_v2
        from app.services.capacity import execution_state, DiskScalarObjects
        state = execution_state()
        self.by_type = DiskScalarObjects(state.database(), 'evidence_entity_types') if state else {}
        for aid, a in scorer.index.alerts.items():
            types = defaultdict(set)
            for eid in a.entity_ids:
                types[scorer.index.entities[eid].type.value].add(eid)
            self.by_type[aid] = dict(types)

    def hot(self, eid):
        idx, c = self.scorer.index, self.scorer.algorithm.candidate
        return idx.df[eid] >= c.hot_entity_min_count and idx.df[eid]/idx.N >= c.hot_entity_ratio

    def evaluate(self, a, b, values, features, relations, refused, source_state, hard):
        scorer, cfg, idx = self.scorer, self.cfg, self.scorer.index
        gate = cfg.gate
        dimensions = []
        def add(name, family, state, strength=0.0, weight=1.0, entities=()):
            dimensions.append(dict(dimension=name, family=family, state=state, weight=weight,
                                   strength=strength, entity_ids=sorted(set(entities))))
        def state(observable, strength):
            return "UNAVAILABLE" if not observable else "AVAILABLE_MATCH" if strength > 0 else "AVAILABLE_MISMATCH"
        add("time.distance", "time", "AVAILABLE_MATCH" if values["time"] > 0 else "AVAILABLE_MISMATCH", values["time"])
        af, bf = self.by_type[a.alert_id], self.by_type[b.alert_id]
        selected, strong, identifiers = defaultdict(list), set(), set()
        for feature in features:
            kind, eid = feature["type"], feature["entity_id"]
            modifier = cfg.entity_quality_rarity_floor + (1-cfg.entity_quality_rarity_floor)*feature["rarity"]
            strength = modifier * feature["role_factor"] * feature["descriptor_factor"]
            selected[kind].append((strength, eid))
            specific = kind not in gate.specific_entity_types or feature["rarity"] >= gate.specific_minimum_rarity
            instance = kind != "PROCESS" or scorer.is_instance(eid)
            if kind in gate.strong_entity_types and instance and specific and not self.hot(eid) and strength >= gate.strong_minimum_strength:
                strong.add("entity." + kind)
            if not self.hot(eid) and strength >= gate.strong_minimum_strength:
                if kind == "PROCESS" and scorer.is_instance(eid):
                    identifiers.add("entity.PROCESS")
                if kind == "SESSION" and feature["rarity"] >= gate.strong_identifier_minimum_rarity:
                    if scorer.settings[a.source_namespace].session_scope is not None and scorer.settings[b.source_namespace].session_scope is not None:
                        identifiers.add("entity.SESSION")
        for kind, weight in sorted(scorer.algorithm.entity.weights.items()):
            observable = bool(af.get(kind)) and bool(bf.get(kind))
            # Several values of one type cannot swamp the other dimensions.
            strength = max((s for s, _ in selected[kind]), default=0.0)
            add("entity." + kind, "entity", state(observable, strength), strength, weight, [e for _, e in selected[kind]])
        semantic = {}
        for field, weight in sorted(cfg.semantic_weights.items()):
            left, right = getattr(a, field), getattr(b, field)
            if field == "category":
                observable = a.category.value != "unknown" and b.category.value != "unknown"
                strength = values["behavior"] if observable else 0.0
                st = state(observable, strength)
            elif a.source_namespace != b.source_namespace:
                # Vendor identifiers/text are not a global equivalence mapping.
                strength, st = 0.0, "NOT_APPLICABLE"
            else:
                observable = left is not None and right is not None
                strength = 1.0 if observable and left == right else 0.0
                st = state(observable, strength)
            add("semantic." + field, "behavior", st, strength, weight)
            semantic[field] = strength
        add("topology.attested_relation", "relation", state(bool(relations or refused), values["relation"]), values["relation"],
            entities=[e for r in relations for e in (r.source_entity_id, r.target_entity_id)])
        network_observable, network_strength, network_ids = False, 0.0, []
        for src, dst in scorer.ordered_pairs(a, b):
            l = [e for e in src.entity_ids if "dst_ip" in idx.roles[src.alert_id][e]]
            r = [e for e in dst.entity_ids if "src_ip" in idx.roles[dst.alert_id][e]]
            network_observable |= any(idx.entities[x].scope == idx.entities[y].scope for x in l for y in r)
            for eid in sorted(set(l) & set(r)):
                modifier = cfg.entity_quality_rarity_floor + (1-cfg.entity_quality_rarity_floor)*idx.rarity(eid, scorer.algorithm.entity)
                network_strength = max(network_strength, scorer.algorithm.entity.role_factors.src_dst_bridge*modifier)
                network_ids.append(eid)
        add("topology.network_continuity", "relation", state(network_observable, network_strength), network_strength, entities=network_ids)
        # A raw endpoint match remains undirected evidence, never VerifiedRelation.
        non_hot_network = any(not self.hot(e) for e in network_ids)
        if non_hot_network and network_strength >= gate.topology_support_minimum:
            strong.add("topology.network_continuity")
        source_st = ("UNAVAILABLE" if source_state == "unknown" else "NOT_APPLICABLE" if source_state == "confirmed_same_origin"
                     else state(True, values["source"]))
        add("context.independent_complement", "source", source_st, values["source"])
        dimensions.sort(key=lambda d: d["dimension"])
        strengths, available = {}, []
        for family in FAMILIES:
            dims = [d for d in dimensions if d["family"] == family and d["state"].startswith("AVAILABLE")]
            denominator = math.fsum(d["weight"] for d in dims)
            strengths[family] = (max((d["strength"] for d in dims), default=0) if family == "relation" else
                math.fsum(d["weight"]*d["strength"] for d in dims)/denominator if denominator else 0.0)
            if denominator:
                available.append(family)
        weights = {k: getattr(scorer.algorithm.score.weights, k) for k in FAMILIES}
        aw = math.fsum(weights[k] for k in available)
        mw = math.fsum(weights[k]*strengths[k] for k in available)
        tw = math.fsum(weights.values())
        quality, mass = mw/aw if aw else 0.0, mw/tw if tw else 0.0
        temporal = strengths["time"] >= gate.temporal_support_minimum
        # Rule/category/signature alone never supply the strong half of a gate.
        semantic_support = strengths["behavior"] >= gate.semantic_support_minimum
        supports = int(temporal) + int(semantic_support)
        attested = bool(relations) and values["relation"] >= scorer.algorithm.chain.explicit_relation_minimum
        if mass < gate.minimum_mass:
            passed, reason = False, "minimum_evidence_mass"
        elif attested or identifiers:
            passed, reason = True, "C_verified_identifier_or_attested_relation"
        elif strong and supports:
            passed, reason = True, "A_strong_context_and_independent_support"
        elif semantic_support and non_hot_network and network_strength >= gate.topology_support_minimum and temporal:
            passed, reason = True, "B_semantic_and_topology_with_time"
        else:
            passed, reason = False, "no_sufficient_independent_evidence_pattern"
        raw = cfg.quality_factor*quality + cfg.mass_factor*mass - scorer.algorithm.score.weights.conflict*values["conflict"] - scorer.algorithm.score.weights.duplicate*values["duplicate"]
        score = min(1.0, max(0.0, raw))
        threshold_passed = score >= scorer.algorithm.score.correlation_threshold
        decision = ("REJECT_GUARD" if hard else "REJECT_INSUFFICIENT_EVIDENCE" if not passed else
                    "REJECT_LOW_SCORE" if not threshold_passed else "ACCEPT")
        audit = dict(version="v2", quality_factor=cfg.quality_factor, mass_factor=cfg.mass_factor,
            family_weights=weights, family_strengths=strengths, dimensions=dimensions,
            available_weight=aw, matched_weight=mw, total_configured_weight=tw,
            normalized_quality=quality, evidence_mass=mass,
            strong_evidence_count=len(strong)+int(attested), supporting_evidence_count=supports,
            evidence_gate_passed=passed, gate_reason=reason, threshold=scorer.algorithm.score.correlation_threshold,
            threshold_passed=threshold_passed, decision=decision)
        for name, st in (("matched_evidence", "AVAILABLE_MATCH"), ("mismatched_evidence", "AVAILABLE_MISMATCH"),
                         ("unavailable_evidence", "UNAVAILABLE"), ("not_applicable_evidence", "NOT_APPLICABLE")):
            audit[name] = [d["dimension"] for d in dimensions if d["state"] == st]
        audit["available_evidence"] = [d["dimension"] for d in dimensions if d["state"].startswith("AVAILABLE")]
        return raw, score, audit
