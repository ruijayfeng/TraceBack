"""Proof bounds and counterfactual arithmetic on frozen production components."""

from collections import Counter, defaultdict
from itertools import combinations
import math

from evaluation.io.diagnostics import VALUES


def formula_witness(config):
    """Synthetic satisfiability witness using the unmodified production scorer."""
    from datetime import datetime, timedelta, timezone
    from app.adapters.base import AdapterSettings
    from app.correlation.index import AlertIndex
    from app.correlation.scoring import CorrelationScorer
    from app.entities.extraction import extract_entities
    from app.models import CanonicalAlert
    from app.utils.stable_id import id_for, raw_fingerprint, utc_text
    def alert(name, seconds=0, **fields):
        data = {"timestamp": utc_text(datetime(2022,1,1,tzinfo=timezone.utc)+timedelta(seconds=seconds)),
                "source_type":"wazuh", "source_namespace":"synthetic-diagnostic",
                "source_record_id":name, **fields}
        raw = {"synthetic_fixture":name, **data}
        data.update(raw_alert=raw,raw_fingerprint=raw_fingerprint(raw),
                    field_provenance={k:{"raw_pointer":"/"+k,"transform":"synthetic-diagnostic-v1"} for k in data if k!="source_namespace"})
        data["alert_id"] = id_for("CanonicalAlert",data)
        return CanonicalAlert.model_validate(data)
    start = utc_text(datetime(2022,1,1,tzinfo=timezone.utc))
    common = {"host":"synthetic-host","account":"synthetic-account","session":"synthetic-session",
              "file":"/synthetic/context", "command":"synthetic command"}
    parent = {"pid":1,"name":"synthetic-parent","start_time":start}
    x = alert("synthetic-parent-alert",category="process_execution",process=parent,**common)
    y = alert("synthetic-child-alert",1,category="privilege_escalation",parent_process=parent,
              process={"pid":2,"name":"synthetic-child","start_time":start},**common)
    background = [alert("synthetic-background-"+str(i),20000+i*9000,host="synthetic-other-"+str(i)) for i in range(64)]
    settings = {"synthetic-diagnostic":AdapterSettings("synthetic-diagnostic","synthetic","synthetic")}
    extracted = extract_entities([x,y,*background],settings)
    index = AlertIndex(extracted.alerts,(),extracted.entities)
    scorer = CorrelationScorer(index,config,settings)
    pair = scorer.score_pair(x.alert_id,y.alert_id)
    return {"kind":"synthetic satisfiability witness, not real-data capability or GT",
            "score":pair.score,"values":pair.values,"contributions":pair.contributions,
            "valid":pair.valid,"rejection_codes":pair.rejection_codes,
            "passes_frozen_threshold":pair.valid and pair.score>=config.algorithm.score.correlation_threshold}


def component_maxima(config):
    a = config.algorithm
    return {"time": 1.0, "entity": 1.0, "relation": max(a.relation.scores.values()),
            "behavior": max(a.behavior.same_category, a.behavior.unknown_category,
                            a.behavior.unlisted_transition, *(r.score for r in a.behavior.transitions)),
            "source": max(a.source.same_type_independent_score,
                          a.source.different_type_confirmed_independent_unlisted_score,
                          *(r.score for r in a.source.complement_rules)),
            "conflict": max(a.conflict.strengths.model_dump().values()), "duplicate": 1.0}


def component_counterfactual(values, contributions, config):
    weights = config.algorithm.score.weights.model_dump()
    maxima = component_maxima(config)
    threshold = config.algorithm.score.correlation_threshold
    raw = sum(contributions.values())
    rows, benefits = [], {}
    for k in VALUES:
        sign = -1 if k in {"conflict", "duplicate"} else 1
        change = sign * weights[k] * (maxima[k]-values[k])
        score = max(0, min(1, raw+change))
        source_gate_unavailable = k=="source" and not any(m.rules for m in config.mapping_files["source.independence_mapping_files"])
        rows.append({"member": k, "actual_value": values[k], "replacement": maxima[k], "final_score": score,
                     "score_passes": score>=threshold, "edge_guaranteed": False,
                     "replacement_domain": "numerical member maximum (independent formula envelope)",
                     "configuration_gate_known_unavailable": source_gate_unavailable,
                     "source_configuration_feasible_maximum": 0.0 if source_gate_unavailable else None,
                     "interpretation": "algebraic only; may require unavailable fields or incompatible evidence"})
        if k not in {"conflict", "duplicate"}:
            benefits[k] = change
    minimum, sets = None, []
    for count in range(1, len(benefits)+1):
        for keys in combinations(benefits, count):
            score = max(0, min(1, raw + sum(benefits[k] for k in keys)))
            if score>=threshold:
                sets.append({"members": list(keys), "final_score": score})
        if sets:
            minimum = count
            break
    # Penalty relief is separately disclosed; increasing a penalty is harmful.
    relief = {k: max(0, min(1, raw-contributions[k])) for k in ("conflict", "duplicate")}
    return {"single_member_to_allowed_maximum": rows, "minimum_positive_members_to_maximum": minimum,
            "minimal_sets": sets, "penalty_to_zero_scores": relief,
            "does_not_create_evidence_or_edges": True}


def reachability(index, scorer, config, observed):
    a = config.algorithm
    weights = a.score.weights.model_dump()
    maxima = component_maxima(config)
    box = min(1, sum(weights[k]*maxima[k] for k in VALUES if k not in {"conflict", "duplicate"}))
    # CanonicalAlert single-value fields limit possible shared entities. IP and
    # PROCESS have two roles; all others have one. This is a relaxation because
    # instance identities, chronology, mappings and penalties may not co-occur.
    counts = {k: 2 if k in {"IP", "PROCESS"} else 1 for k in a.entity.weights}
    per_type = {k: min(a.entity.max_contributors_per_type, counts[k]) for k in counts}
    role_max = max(a.entity.role_factors.model_dump().values())
    entity_envelope = 1-math.prod((1-min(1, a.entity.weights[k]*role_max))**per_type[k] for k in sorted(per_type))
    # Without nonempty independence mapping, the actual complement function
    # can return only unknown/same_origin, both forced to zero.
    source_cap = maxima["source"] if scorer.has_independence_mappings else 0.0
    cfg_bound = min(1, weights["time"] + weights["entity"]*entity_envelope
                    + weights["relation"]*maxima["relation"] + weights["behavior"]*maxima["behavior"]
                    + weights["source"]*source_cap)
    categories = Counter(a.category.value for a in index.alerts.values())
    relation_count = sum(len(a.relations) for a in index.alerts.values())
    if relation_count or scorer.instances:
        raise ValueError("dataset_zero_relation_proof_unavailable")
    if scorer.has_independence_mappings:
        raise ValueError("dataset_zero_source_proof_unavailable")
    # Complete data proof: verify_relations() requires either full process
    # instances or an existing attested AlertRelation; neither exists anywhere.
    r_cap = s_cap = 0.0
    category_examples = {c: next(v for v in index.alerts.values() if v.category.value == c) for c in sorted(categories)}
    b_cap = max(scorer.behavior_value(x,y) for x in category_examples.values() for y in category_examples.values())
    coarse = weights["time"] + weights["entity"] + weights["relation"]*r_cap + weights["behavior"]*b_cap + weights["source"]*s_cap
    # For any pair, shared features are a subset of either endpoint's real
    # entity IDs. Replace partner role by its maximum, retain actual rarity,
    # descriptor factor, df>=2 and top-per-type cap. Monotonicity of noisy-OR
    # proves E(pair)<=min(Ecap(left),Ecap(right)). No feature maxima are scored
    # as a synthetic support pair.
    caps, witness = {}, None
    for aid, alert in index.alerts.items():
        by_type = defaultdict(list)
        for eid in alert.entity_ids:
            if index.df[eid]<2:
                continue
            e = index.entities[eid]
            factor = a.entity.process_descriptor_factor if e.type.value == "PROCESS" and not scorer.is_instance(eid) else 1
            x = min(1, a.entity.weights[e.type.value]*index.rarity(eid,a.entity)*role_max*factor)
            by_type[e.type.value].append((x,eid))
        features = [p for kind in sorted(by_type) for p in sorted(by_type[kind],key=lambda p:(-p[0],p[1]))[:a.entity.max_contributors_per_type]]
        entity = 1-math.prod(1-x for x,_ in features)
        best_behavior = max(max(scorer.behavior_value(alert,b),scorer.behavior_value(b,alert)) for b in category_examples.values())
        total = weights["time"] + weights["entity"]*entity + weights["behavior"]*best_behavior
        caps[aid] = total
        item = (total, aid, entity, best_behavior, features)
        if witness is None or (-item[0],item[1])<(-witness[0],witness[1]):
            witness = item
    dataset_bound = witness[0]
    if box<a.score.correlation_threshold:
        classification="Formula-Unreachable"
    elif dataset_bound<a.score.correlation_threshold:
        classification="Dataset-Unreachable"
    elif observed>=a.score.correlation_threshold:
        classification="Reachable"
    else:
        raise ValueError("upper_bound_alone_does_not_prove_sparse_reachability")
    return {"edge_threshold": a.score.correlation_threshold, "classification": classification,
            "mathematical_box_upper_bound": box,
            "mathematical_box_kind": "exact maximum of seven independent [0,1] component domains; joint field attainability is separate",
            "box_requirements": {k: maxima[k] if k not in {"conflict","duplicate"} else 0 for k in VALUES},
            "configuration_allowed_upper_bound": cfg_bound, "configuration_bound_kind": "upper bound, not asserted joint attainable maximum",
            "configuration_entity_envelope": entity_envelope, "canonical_entity_multiplicity_cap": per_type,
            "configuration_source_cap": source_cap, "configuration_source_reason": "no independence mapping rules => S=0 for every possible input under this configuration",
            "dataset_constrained_maximum_reachable_score": dataset_bound, "dataset_result_kind": "upper bound",
            "coarse_dataset_upper_bound": coarse, "observed_maximum": observed,
            "dataset_bound_scope": "all original distinct-group pairs, including non-Potential and policy-pruned pairs; not just admitted pairs",
            "dataset_component_caps": {"time":1.0,"relation":r_cap,"source":s_cap,"behavior":b_cap},
            "proof": {"category_counts": dict(sorted(categories.items())), "upstream_alert_relation_count": relation_count,
                      "full_process_instance_entity_count": len(scorer.instances),
                      "independence_mapping_rule_count": sum(len(m.rules) for m in scorer.independence_mappings),
                      "relation_zero": "verify_relations branches require process instances or existing relations; both absent across entire dataset",
                      "source_zero": "independence() cannot confirm independence with no mapping rule; complement() returns zero",
                      "behavior_cap": "enumerated production behavior_value for every actual category pair, both directions, disregarding chronology to obtain upper bound",
                      "entity_cap": "actual endpoint entities+frozen df/N rarity; df>=2; partner role maximum; per-type production cap; monotone noisy-OR",
                      "score_cap": "T<=1; R=S=0; B bounded per endpoint category; C,D>=0 ignored; max over all endpoints bounds every real pair",
                      "endpoint_bound_witness": {"alert_id":witness[1],"entity_upper_bound":witness[2],
                                                 "behavior_upper_bound":witness[3],"entity_features":[{"x":x,"entity_id":i} for x,i in witness[4]]},
                      "is_real_pair_witness": False},
            "mathematically_reachable": None, "formula_witness": "run frozen-config synthetic production scorer in dedicated test; no GT; evidence recorded by runner",
            "dataset_threshold_reachable": dataset_bound>=a.score.correlation_threshold,
            "necessary_relation_score_if_S_zero_and_T_E_B_at_dataset_caps": max(0,(a.score.correlation_threshold-coarse)/weights["relation"]),
            "parameter_optimality_claim": False}
