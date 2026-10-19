"""Fail-closed fact, reference, direction and controlled-text validation."""

import re

from app.models import AIClaim, AIExplanation
from app.models.ai import GroundedProposition
from app.models.enums import ClaimKind, ClaimSection, GroundingStatus
from app.utils.stable_id import canonical_json, id_for, pointer_set
from .prompts import ACTION_TEMPLATES, RECOMMENDATION_REASON, RISK_TEXT, UNCERTAINTY_TEXT, render_fact, render_mapping


SUBJECT_TABLES = {"alert": "alerts", "node": "nodes", "chain_edge": "edges", "correlation_edge": "correlations"}
EDGE_FIELDS = {"source_node_id", "target_node_id", "relation_type", "reasons", "score_breakdown"}


def references(propositions, facts):
    """Minimum frozen claim closure, including full endpoint alert support."""
    nodes, edges, alerts, objects = set(), set(), set(), set()
    for p in propositions:
        kind, sid = p.subject_type, p.subject_id
        subject = facts[SUBJECT_TABLES[kind]][sid]
        objects.add(sid)
        if kind == "alert":
            alerts.add(sid)
        elif kind == "node":
            nodes.add(sid)
            alerts.update(subject["alert_ids"])
        else:
            if kind == "correlation_edge":
                supporting = sorted(eid for eid, edge in facts["edges"].items() if sid in edge["correlation_edge_ids"])
                if not supporting:
                    raise ValueError("correlation_reference_requires_chain_edge")
                # An undirected cor edge never supplies causal direction.
                selected = facts["edges"][supporting[0]]
            else:
                selected = subject
            edges.add(selected["edge_id"])
            nodes.update((selected["source_node_id"], selected["target_node_id"]))
            alerts.update(selected["alert_ids"])
            for nid in (selected["source_node_id"], selected["target_node_id"]):
                alerts.update(facts["nodes"][nid]["alert_ids"])
            if kind == "correlation_edge":
                alerts.update(subject["support_pair"].values())
    objects.update(nodes | edges | alerts)
    return {"object_refs": sorted(objects), "node_refs": sorted(nodes), "edge_refs": sorted(edges), "alert_refs": sorted(alerts)}


def evidence_for(refs, data):
    return pointer_set([p for oid in refs["object_refs"] for p in data["object_evidence"][oid]])


def make_finding(data, propositions):
    """Provide copyable, already-grounded wording to any configured provider."""
    ps = [GroundedProposition.model_validate(p) for p in propositions]
    refs = references(ps, data["facts"])
    return {"statement": render_fact(ps, data["facts"]), **refs, "evidence_refs": evidence_for(refs, data),
            "propositions": [p.model_dump(mode="json") for p in ps]}


def fact_claim(item, section=ClaimSection.RISK):
    claim = {"kind": ClaimKind.FACT, "section": section, "text": item["statement"],
             "node_ids": item["node_refs"], "edge_ids": item["edge_refs"], "alert_ids": item["alert_refs"],
             "propositions": item["propositions"], "grounding_status": GroundingStatus.VALIDATED}
    claim["claim_id"] = id_for("AIClaim", claim)
    return AIClaim.model_validate(claim)


def mapping_options(data, catalog):
    """Candidates express existing alert semantics, never discover graph facts."""
    facts, findings, options = data["facts"], {}, []
    for nid, node in sorted(facts["nodes"].items()):
        for aid in node["alert_ids"]:
            alert = facts["alerts"][aid]
            for technique in sorted(catalog.techniques, key=lambda t: t.technique_id):
                if not catalog.support(technique, alert, facts["entities"]):
                    continue
                item = make_finding(data, [
                    {"subject_type": "node", "subject_id": nid, "field": "category", "value": node["category"]},
                    *[{"subject_type": "alert", "subject_id": aid, "field": field, "value": alert[field]}
                      for field in ("category", "entity_occurrences")]])
                cid = fact_claim(item).claim_id
                findings[cid] = item
                refs = {k: item[k] for k in ("object_refs", "node_refs", "edge_refs", "alert_refs", "evidence_refs")}
                options.append({"technique_id": technique.technique_id, "technique_name": technique.technique_name,
                    "tactic": technique.tactics[0], "parent_id": technique.parent_id, "confidence": "tentative",
                    "catalog_version": catalog.version, "reason": render_mapping(technique, [cid]),
                    "supporting_fact_ids": [cid], **refs})
    return [findings[cid] for cid in sorted(findings)], options


def validate_mappings(data, drafts, accepted_claims):
    """Reject individual mappings without publishing their untrusted prose."""
    from .attack_catalog import AttackCatalog
    from .explanation import AttackTechniqueDraft
    from pydantic import ValidationError
    catalog = AttackCatalog.model_validate(data["attack_catalog"])
    entries = {t.technique_id: t for t in catalog.techniques}
    _, candidates = mapping_options(data, catalog)
    valid_facts = {c.claim_id for c in accepted_claims if c.kind == ClaimKind.FACT}
    accepted, rejected, claims, seen = [], [], [], set()
    for index, raw in enumerate(drafts):
        errors = []
        try:
            item = AttackTechniqueDraft.model_validate(raw)
        except ValidationError:
            rejected.append({"index": index, "validation_errors": ["mapping_schema_invalid"]})
            continue
        value = item.model_dump(mode="json")
        technique = entries.get(item.technique_id)
        if technique is None:
            errors.append("unknown_technique")
        else:
            if technique.technique_name != item.technique_name:
                errors.append("technique_name_mismatch")
            if item.tactic not in technique.tactics:
                errors.append("technique_tactic_mismatch")
            if technique.parent_id != item.parent_id:
                errors.append("subtechnique_parent_mismatch")
        if item.catalog_version != catalog.version:
            errors.append("catalog_version_mismatch")
        if not set(item.supporting_fact_ids) <= valid_facts:
            errors.append("invalid_supporting_fact_reference")
        if not set(item.object_refs) <= set(data["object_evidence"]):
            errors.append("invalid_object_reference")
        if not set(item.node_refs) <= data["facts"]["nodes"].keys():
            errors.append("invalid_node_reference")
        if not set(item.edge_refs) <= data["facts"]["edges"].keys():
            errors.append("invalid_edge_reference")
        if not set(item.alert_refs) <= data["facts"]["alerts"].keys():
            errors.append("invalid_alert_reference")
        if any(canonical_json(p) not in {canonical_json(ref) for ref in data["evidence_refs"]}
               for p in value["evidence_refs"]):
            errors.append("invalid_evidence_reference")
        # Whole candidate equality checks semantic eligibility + exact reason
        # and Fact -> Object -> Evidence binding, rather than just ID presence.
        for field in ("object_refs", "node_refs", "edge_refs", "alert_refs", "supporting_fact_ids"):
            if len(value[field]) != len(set(value[field])):
                errors.append("mapping_reference_duplicate")
            value[field] = sorted(value[field])
        if len(value["evidence_refs"]) != len(pointer_set(value["evidence_refs"])):
            errors.append("mapping_reference_duplicate")
        value["evidence_refs"] = pointer_set(value["evidence_refs"])
        candidate = next((c for c in candidates if c["technique_id"] == item.technique_id
                          and c["supporting_fact_ids"] == value["supporting_fact_ids"]), None)
        if candidate is None:
            errors.append("unsupported_technique")
        elif canonical_json(value) != canonical_json(candidate):
            errors.append("mapping_grounding_mismatch")
        if errors:
            rejected.append({"index": index, "validation_errors": sorted(set(errors))})
            continue
        support = next(c for c in accepted_claims if c.claim_id == item.supporting_fact_ids[0])
        claim = {"kind": ClaimKind.ATTACK_MAPPING, "section": ClaimSection.ATTACK_MAPPING,
                 "text": item.reason, "node_ids": item.node_refs, "edge_ids": item.edge_refs,
                 "alert_ids": item.alert_refs, "propositions": [p.model_dump(mode="json") for p in support.propositions],
                 "attack_mapping": {"technique_id": item.technique_id, "technique_name": item.technique_name,
                     "tactic": item.tactic, "catalog_version": catalog.version, "rationale": item.reason},
                 "grounding_status": GroundingStatus.VALIDATED}
        claim["claim_id"] = id_for("AIClaim", claim)
        if claim["claim_id"] not in seen:
            seen.add(claim["claim_id"])
            claims.append(AIClaim.model_validate(claim))
            accepted.append({**value, "claim_id": claim["claim_id"], "mapping_status": "validated"})
    return sorted(accepted, key=lambda c: (c["technique_id"], c["claim_id"])), rejected, claims


def entity_tokens(text):
    """Basic literal guard, supplemented by exact controlled text below.

    Unmarked host/account names and semantic substitutions cannot be recognized
    universally by regex. They are rejected by template equality as well.
    """
    return set(re.findall(r"https?://[^\s\"，。]+|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-fA-F0-9]{32,128}\b|"
                          r"\b[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+\b|"
                          r"(?:hostname|host|account|domain|主机|账户|域名)\s*[:=]\s*[^\s，。]+", text))


def validate_draft(context, draft, metadata):
    data = context.data
    facts = data["facts"]
    subjects = {(kind, sid): value for kind, table in SUBJECT_TABLES.items() for sid, value in facts[table].items()}
    allowed = set(data["object_evidence"]) | {data["incident"]["incident_id"], data["chain_id"]}
    errors, claims, sections = [], [], {"summary": [], "key_findings": [], "attack_progression": []}
    rejected_claims = []
    if draft.incident_id != data["incident"]["incident_id"]:
        errors.append("cross_incident_reference")
    if set(draft.uncertainties) - data["uncertainties"].keys():
        errors.append("unsupported_uncertainty")
    edge_order = data["ordered_edge_ids"]
    if not edge_order and draft.attack_progression:
        errors.append("nonexistent_attack_path")
    elif edge_order and len(draft.attack_progression) != len(edge_order):
        errors.append("incomplete_attack_progression")
    if errors:
        return None, sorted(set(errors))
    for section, items, claim_section in (("summary", draft.summary, ClaimSection.SUMMARY),
            ("key_findings", draft.key_findings, ClaimSection.RISK),
            ("attack_progression", draft.attack_progression, ClaimSection.ATTACK_PATH)):
        for index, item in enumerate(items):
            errors = []
            if any(ref not in allowed for ref in item.object_refs):
                errors.append("invalid_object_reference")
            if any(ref not in facts["nodes"] for ref in item.node_refs):
                errors.append("invalid_node_reference")
            if any(ref not in facts["edges"] for ref in item.edge_refs):
                errors.append("invalid_edge_reference")
            if any(ref not in facts["alerts"] for ref in item.alert_refs):
                errors.append("invalid_alert_reference")
            provided_evidence = pointer_set([p.model_dump(mode="json") for p in item.evidence_refs])
            accepted_evidence = {canonical_json(p) for p in data["evidence_refs"]}
            if any(canonical_json(p) not in accepted_evidence for p in provided_evidence):
                errors.append("invalid_evidence_reference")
            try:
                ps = [GroundedProposition.model_validate(p.model_dump(), context={"subjects": subjects}) for p in item.propositions]
                refs = references(ps, facts)
            except (ValueError, KeyError):
                errors.append("unsupported_proposition")
                rejected_claims.append({"section": section, "index": index, "validation_errors": sorted(set(errors))})
                continue
            for field, required in refs.items():
                values = getattr(item, field)
                if len(values) != len(set(values)) or set(values) != set(required):
                    errors.append("reference_closure_mismatch")
            if provided_evidence != evidence_for(refs, data):
                errors.append("evidence_closure_mismatch")
            expected = render_fact(ps, facts)
            if entity_tokens(item.statement) - entity_tokens(expected):
                errors.append("entity_hallucination")
            if item.statement != expected:
                errors.append("unsupported_fact_text")
            if section == "attack_progression":
                eid = edge_order[index] if index < len(edge_order) else None
                fields = {p.field for p in ps if p.subject_type == "chain_edge" and p.subject_id == eid}
                if item.step != index + 1 or item.edge_refs != [eid] or not EDGE_FIELDS <= fields:
                    errors.append("attack_direction_or_order_mismatch")
            if errors:
                rejected_claims.append({"section": section, "index": index, "validation_errors": sorted(set(errors))})
                continue
            claim = {"kind": ClaimKind.FACT, "section": claim_section, "text": expected,
                     "node_ids": refs["node_refs"], "edge_ids": refs["edge_refs"], "alert_ids": refs["alert_refs"],
                     "propositions": ps, "grounding_status": GroundingStatus.VALIDATED}
            claim["claim_id"] = id_for("AIClaim", {**claim, "propositions": [p.model_dump(mode="json") for p in ps]})
            claims.append(AIClaim.model_validate(claim, context={"subjects": subjects}))
            sections[section].append({**item.model_dump(), "claim_id": claim["claim_id"]})
    actions = []
    for index, action in enumerate(draft.recommended_actions):
        if (action.recommendation != ACTION_TEMPLATES[action.action] or action.reason != RECOMMENDATION_REASON
                or any(ref not in allowed for ref in action.related_object_refs)):
            rejected_claims.append({"section": "recommended_actions", "index": index,
                                    "validation_errors": ["unsupported_recommendation"]})
            continue
        # References are not authorization for arbitrary prose. Host/account
        # suggestions additionally require that type in the selected evidence.
        refs = set(action.related_object_refs)
        linked_alerts = set(refs & facts["alerts"].keys())
        for oid in refs:
            if oid in data["object_evidence"]:
                linked_alerts.update(p["alert_id"] for p in data["object_evidence"][oid])
        needed = {"inspect_host": "HOST", "inspect_account": "ACCOUNT"}.get(action.action)
        if needed and not any(e["type"] == needed and set(e["alert_ids"]) & linked_alerts for e in facts["entities"].values()):
            rejected_claims.append({"section": "recommended_actions", "index": index,
                                    "validation_errors": ["recommendation_missing_entity"]})
            continue
        claim = {"kind": ClaimKind.RECOMMENDATION, "section": ClaimSection.RECOMMENDATIONS,
                 "text": action.recommendation + " " + action.reason,
                 "alert_ids": sorted(linked_alerts), "grounding_status": GroundingStatus.VALIDATED}
        claim["claim_id"] = id_for("AIClaim", claim)
        claims.append(AIClaim.model_validate(claim))
        actions.append(action)
    # SOC assessment is a read-only view of observed categories, entities,
    # severity and algorithm confidence. It never asserts attack success.
    assessment = []
    for nid, node in sorted(facts["nodes"].items()):
        item = make_finding(data, [
            *[{"subject_type": "node", "subject_id": nid, "field": field, "value": node[field]}
              for field in ("category", "confidence")],
            *[{"subject_type": "alert", "subject_id": aid, "field": field, "value": facts["alerts"][aid][field]}
              for aid in node["alert_ids"] for field in ("category", "severity", "entity_occurrences")]])
        claim = fact_claim(item)
        claims.append(claim)
        assessment.append({**item, "claim_id": claim.claim_id})
    techniques, rejected, mapping_claims = validate_mappings(data, draft.attack_techniques, claims)
    claims.extend(mapping_claims)
    explanation = {"analysis_id": data["analysis_id"], "incident_id": data["incident"]["incident_id"],
                   "chain_id": data["chain_id"], "input_digest": context.input_digest, **metadata,
                   "claims": [c.model_dump(mode="json") for c in claims], "grounding_status": GroundingStatus.VALIDATED}
    explanation["explanation_id"] = id_for("AIExplanation", explanation)
    entities = [{"entity_id": eid, "type": e["type"], "value": e["value"], "alert_refs": e["alert_ids"],
                 "evidence_refs": data["object_evidence"][eid]} for eid, e in sorted(facts["entities"].items())
                if e["type"] in {"IP", "HOST", "ACCOUNT", "SESSION"}]
    return {**sections, "explanation": AIExplanation.model_validate(explanation),
            "assessment": assessment, "attack_techniques": techniques, "rejected_mappings": rejected,
            "key_entities": entities, "risk": {"observed_severity": data["incident"]["severity"],
                "confidence": "not_calibrated", "statement": RISK_TEXT,
                "supporting_fact_ids": sorted({a["claim_id"] for a in assessment})},
            "recommended_actions": actions, "rejected_claims": rejected_claims}, []
