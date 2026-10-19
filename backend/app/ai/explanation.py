"""Immutable whitelist context, transport schemas and explanation service.

Frozen AIClaim/AIExplanation are reused unchanged. Product sections are views
of validated claims; they are not an alternative fact storage contract.
"""

from dataclasses import dataclass
import heapq
import json
from threading import Lock
from typing import Annotated, Literal

from pydantic import Field, ValidationError

from app.models import AIExplanation
from app.models.ai import PROPOSITION_FIELDS, GroundedProposition
from app.models.alerts import EvidencePointer
from app.models.base import AnalysisID, Digest, IncidentID, Json, StrictModel, Text, resolve_pointer
from app.utils.stable_id import canonical_json, content_digest, id_for, pointer_set
from .prompts import (ACTION_TEMPLATES, GROUNDING_VERSION, PROMPT_VERSION, RECOMMENDATION_REASON,
                      TEMPLATE_VERSION, UNCERTAINTY_TEXT)
from .provider import ProviderError


class FindingDraft(StrictModel):
    statement: Text
    object_refs: list[Text]
    node_refs: list[Text]
    edge_refs: list[Text]
    alert_refs: Annotated[list[Text], Field(min_length=1)]
    evidence_refs: Annotated[list[EvidencePointer], Field(min_length=1)]
    propositions: Annotated[list[GroundedProposition], Field(min_length=1)]


class ProgressionDraft(FindingDraft):
    step: Annotated[int, Field(ge=1)]


class ActionDraft(StrictModel):
    action: Literal["verify_alert", "inspect_host", "inspect_account", "collect_evidence", "confirm_before_containment"]
    recommendation: Text
    reason: Text
    related_object_refs: list[Text]


class AttackTechniqueDraft(StrictModel):
    technique_id: Text
    technique_name: Text
    tactic: Text
    parent_id: Text | None
    confidence: Literal["tentative"]
    reason: Text
    catalog_version: Text
    supporting_fact_ids: Annotated[list[Text], Field(min_length=1)]
    object_refs: Annotated[list[Text], Field(min_length=1)]
    node_refs: Annotated[list[Text], Field(min_length=1)]
    edge_refs: list[Text]
    alert_refs: Annotated[list[Text], Field(min_length=1)]
    evidence_refs: Annotated[list[EvidencePointer], Field(min_length=1)]


class GroundedTechnique(AttackTechniqueDraft):
    claim_id: Text
    mapping_status: Literal["validated"]


class RejectedMapping(StrictModel):
    index: Annotated[int, Field(ge=0)]
    validation_errors: Annotated[list[Text], Field(min_length=1)]


class RejectedClaim(RejectedMapping):
    section: Literal["summary", "key_findings", "attack_progression", "recommended_actions"]


class KeyEntity(StrictModel):
    entity_id: Text
    type: Literal["IP", "HOST", "ACCOUNT", "SESSION"]
    value: Text
    alert_refs: list[Text]
    evidence_refs: list[EvidencePointer]


class RiskAssessment(StrictModel):
    observed_severity: Text
    confidence: Literal["not_calibrated"]
    statement: Text
    supporting_fact_ids: list[Text]


class ExplanationDraft(StrictModel):
    incident_id: IncidentID
    summary: Annotated[list[FindingDraft], Field(min_length=1)]
    key_findings: list[FindingDraft]
    attack_progression: list[ProgressionDraft]
    uncertainties: list[Text]
    recommended_actions: list[ActionDraft]
    # Parse each mapping independently so one malformed item cannot suppress
    # otherwise valid SOC output. Invalid envelope/JSON still fails as in 07.1.
    attack_techniques: list[Json] = Field(default_factory=list)


class GroundedFinding(FindingDraft):
    claim_id: Text


class GroundedProgression(GroundedFinding):
    step: Annotated[int, Field(ge=1)]


class Uncertainty(StrictModel):
    code: Text
    statement: Text
    object_refs: list[Text]


class ProviderMetadata(StrictModel):
    provider: Text
    model: Text
    prompt_version: Text


class GroundedExplanation(StrictModel):
    analysis_id: AnalysisID
    incident_id: IncidentID
    input_digest: Digest
    status: Literal["available", "unavailable", "validation_failed"]
    detail: Text
    context_status: Literal["context_ready"]
    grounding_status: Literal["pending", "validated", "rejected"]
    provider_metadata: ProviderMetadata | None
    explanation: AIExplanation | None
    summary: list[GroundedFinding]
    key_findings: list[GroundedFinding]
    attack_progression: list[GroundedProgression]
    uncertainties: list[Uncertainty]
    recommended_actions: list[ActionDraft]
    validation_errors: list[Text]
    assessment: list[GroundedFinding] = Field(default_factory=list)
    attack_techniques: list[GroundedTechnique] = Field(default_factory=list)
    rejected_mappings: list[RejectedMapping] = Field(default_factory=list)
    key_entities: list[KeyEntity] = Field(default_factory=list)
    risk: RiskAssessment | None = None
    attack_catalog_version: Text | None = None
    attack_catalog_digest: Digest | None = None
    attack_mapping_version: Text | None = None
    report_markdown: str | None = None
    report_json: dict[str, Json] | None = None
    rejected_claims: list[RejectedClaim] = Field(default_factory=list)
    degraded: bool = False
    generation_status: Literal["succeeded", "provider_unavailable", "provider_failed", "parsing_failed",
                               "grounding_rejected", "partially_rejected"] = "succeeded"
    result_origin: Literal["llm", "deterministic", "mixed"] = "llm"
    generation_digest: Digest | None = None


@dataclass(frozen=True)
class ExplanationContext:
    # No mutable model/raw-alert handle is exposed to a provider.
    payload: str
    input_digest: str

    @property
    def data(self):
        return json.loads(self.payload)


def ordered_edges(chain):
    """Topological traversal of existing directions; ties never add causality."""
    nodes = {n.node_id for n in chain.nodes}
    degree = dict.fromkeys(nodes, 0)
    outgoing = {nid: [] for nid in nodes}
    for edge in chain.edges:
        outgoing[edge.source_node_id].append(edge)
        degree[edge.target_node_id] += 1
    ready = [nid for nid in nodes if degree[nid] == 0]
    heapq.heapify(ready)
    result, visited = [], 0
    while ready:
        nid = heapq.heappop(ready)
        visited += 1
        for edge in sorted(outgoing[nid], key=lambda e: e.edge_id):
            result.append(edge.edge_id)
            degree[edge.target_node_id] -= 1
            if degree[edge.target_node_id] == 0:
                heapq.heappush(ready, edge.target_node_id)
    if visited != len(nodes):
        raise ValueError("context_cycle")
    return result


def build_context(analysis_id, incident, chain, alerts, entities, correlations, *, is_complete=True,
                  template_version=TEMPLATE_VERSION, grounding_version=GROUNDING_VERSION, attack_catalog=None):
    """Only accepted objects from one published snapshot. No discovery calls."""
    models = [incident, chain, *alerts, *entities, *correlations, *chain.nodes, *chain.edges]
    for obj in models:
        type(obj).model_validate_json(obj.model_dump_json())
        if id_for(type(obj).__name__, obj) != getattr(obj, {
            "Incident": "incident_id", "AttackChain": "chain_id", "CanonicalAlert": "alert_id",
            "Entity": "entity_id", "CorrelationEdge": "edge_id", "ChainNode": "node_id", "ChainEdge": "edge_id",
        }[type(obj).__name__]):
            raise ValueError("context_identity_mismatch")
    aids = set(incident.alert_ids)
    alert_map = {a.alert_id: a for a in alerts}
    entity_map = {e.entity_id: e for e in entities}
    cor_map = {c.edge_id: c for c in correlations}
    node_map = {n.node_id: n for n in chain.nodes}
    if (len(alert_map) != len(alerts) or len(entity_map) != len(entities) or len(cor_map) != len(correlations)
            or set(alert_map) != aids or set(entity_map) != set(incident.entity_ids)
            or set(cor_map) != set(incident.correlation_edge_ids) or chain.incident_id != incident.incident_id
            or set(a for n in chain.nodes for a in n.alert_ids) != aids):
        raise ValueError("context_scope_mismatch")
    facts = {"alerts": {}, "nodes": {}, "edges": {}, "correlations": {}, "entities": {}}
    object_evidence = {}
    for aid, alert in sorted(alert_map.items()):
        if not set(alert.entity_ids) <= set(entity_map):
            raise ValueError("context_entity_missing")
        data = alert.model_dump(mode="json")
        facts["alerts"][aid] = {f: data[f] for f in sorted(PROPOSITION_FIELDS["alert"])}
        pointers = [{"alert_id": aid, "pointer": provenance.raw_pointer, "side": "shared"}
                    for field, provenance in sorted(alert.field_provenance.items())
                    if field in PROPOSITION_FIELDS["alert"] or field in {"host", "src_ip", "dst_ip", "account", "session", "process", "parent_process", "url", "domain", "file", "command"}]
        pointers.extend({"alert_id": aid, "pointer": occ.raw_pointer, "side": "shared"} for occ in alert.entity_occurrences)
        if not pointers:
            raise ValueError("context_evidence_missing")
        object_evidence[aid] = pointer_set(pointers)
    for eid, entity in sorted(entity_map.items()):
        local_alert_ids = sorted(set(entity.alert_ids) & aids)
        occurrence_ids = sorted(a.alert_id for a in alerts if eid in a.entity_ids)
        if local_alert_ids != occurrence_ids or not local_alert_ids:
            raise ValueError("context_entity_scope_mismatch")
        data = entity.model_dump(mode="json")
        # A shared entity can occur in other Incidents; do not expose their IDs.
        data["alert_ids"] = local_alert_ids
        facts["entities"][eid] = data
        object_evidence[eid] = pointer_set([{"alert_id": a.alert_id, "pointer": occ.raw_pointer, "side": "shared"}
            for a in alerts for occ in a.entity_occurrences if occ.entity_id == eid])
    for node in chain.nodes:
        if node.incident_id != incident.incident_id or not set(node.entity_ids) <= set(entity_map):
            raise ValueError("context_node_scope_mismatch")
        facts["nodes"][node.node_id] = node.model_dump(mode="json")
        object_evidence[node.node_id] = pointer_set([p for aid in node.alert_ids for p in object_evidence[aid]])
    for cor in correlations:
        if not {cor.source_alert_id, cor.target_alert_id, cor.support_pair.alert_id_src, cor.support_pair.alert_id_dst} <= aids:
            raise ValueError("context_correlation_scope_mismatch")
        if not set(cor.entity_ids) <= set(entity_map):
            raise ValueError("context_correlation_entity_missing")
        facts["correlations"][cor.edge_id] = cor.model_dump(mode="json")
        object_evidence[cor.edge_id] = pointer_set([p for aid in (cor.support_pair.alert_id_src, cor.support_pair.alert_id_dst)
                                                  for p in object_evidence[aid]])
    for edge in chain.edges:
        if (edge.incident_id != incident.incident_id or not set(edge.correlation_edge_ids) <= set(cor_map)
                or not set(edge.alert_ids) <= aids or not set(edge.entity_ids) <= set(entity_map)):
            raise ValueError("context_edge_scope_mismatch")
        selected = cor_map.get(edge.score_breakdown.selected_correlation_edge_id)
        breakdown = edge.score_breakdown.model_dump(mode="json")
        breakdown["selected_correlation_edge_id"] = None
        if selected is None or breakdown != selected.score_breakdown.model_dump(mode="json"):
            raise ValueError("context_score_mismatch")
        facts["edges"][edge.edge_id] = edge.model_dump(mode="json")
        object_evidence[edge.edge_id] = pointer_set([p for nid in (edge.source_node_id, edge.target_node_id)
                                                    for p in object_evidence[nid]])
    for subject in [*chain.nodes, *correlations, *chain.edges]:
        extra = []
        for reason in subject.reasons:
            if not set(reason.alert_ids) <= aids or not set(reason.entity_ids) <= set(entity_map):
                raise ValueError("context_reason_scope_mismatch")
            for pointer in reason.params.get("raw_pointers", []):
                if pointer["alert_id"] not in reason.alert_ids:
                    raise ValueError("context_reason_pointer_scope")
                extra.append(pointer)
        identity = getattr(subject, "node_id", None) or subject.edge_id
        object_evidence[identity] = pointer_set([*object_evidence[identity], *extra])
    evidence = pointer_set([p for refs in object_evidence.values() for p in refs])
    for pointer in evidence:
        resolve_pointer(alert_map[pointer["alert_id"]].raw_alert, pointer["pointer"])
    uncertainty_codes = ["alerts_not_confirmed_attack"]
    if len(aids) == 1:
        uncertainty_codes.append("singleton_incident")
    if not chain.edges:
        uncertainty_codes.append("insufficient_relation")
    if chain.unresolved_correlation_edge_ids:
        uncertainty_codes.append("unknown_direction")
    if any(a.category.value == "unknown" for a in alerts):
        uncertainty_codes.append("unknown_category")
    if any(not a.entity_ids for a in alerts):
        uncertainty_codes.append("missing_entities")
    if not is_complete:
        uncertainty_codes.append("incomplete_analysis")
    # Singleton triage is a separate deterministic SOC projection, not a new
    # proposition family or an expansion of the frozen AI fact whitelist.
    data = {"analysis_id": analysis_id, "incident": {k: v for k, v in incident.model_dump(mode="json").items()
                                                     if k not in {"summary", "single_alert_triage"}},
            "chain_id": chain.chain_id, "chain_status": chain.status, "facts": facts,
            "ordered_edge_ids": ordered_edges(chain), "object_evidence": object_evidence, "evidence_refs": evidence,
            "uncertainties": {k: UNCERTAINTY_TEXT[k] for k in sorted(uncertainty_codes)},
            "action_templates": ACTION_TEMPLATES, "recommendation_reason": RECOMMENDATION_REASON,
            "grounding_version": grounding_version, "template_version": template_version}
    # Copyable templates make the provider's task evidence selection/organization
    # and keep exact-text validation practical with an actual HTTP provider.
    from .grounding import make_finding
    options = {"observations": [], "findings": [], "progression": []}
    for aid, alert in facts["alerts"].items():
        options["observations"].append(make_finding(data, [{"subject_type": "alert", "subject_id": aid,
            "field": f, "value": alert[f]} for f in ("timestamp", "source_type", "category")]))
        options["findings"].append(make_finding(data, [{"subject_type": "alert", "subject_id": aid,
            "field": f, "value": alert[f]} for f in ("severity", "entity_occurrences")]))
    for nid, node in facts["nodes"].items():
        options["findings"].append(make_finding(data, [{"subject_type": "node", "subject_id": nid,
            "field": f, "value": node[f]} for f in ("category", "confidence", "reasons")]))
    for step, eid in enumerate(data["ordered_edge_ids"], 1):
        edge = facts["edges"][eid]
        options["progression"].append({**make_finding(data, [{"subject_type": "chain_edge", "subject_id": eid,
            "field": f, "value": edge[f]} for f in ("source_node_id", "target_node_id", "relation_type", "reasons", "score_breakdown")]), "step": step})
    data["fact_options"] = options
    from .attack_catalog import load_catalog
    from .grounding import mapping_options
    catalog = attack_catalog if attack_catalog is not None else load_catalog()
    data["attack_catalog"] = catalog.snapshot
    data["attack_catalog_digest"] = catalog.digest
    options["mapping_facts"], data["attack_mapping_options"] = mapping_options(data, catalog)
    # Preserve JSON types; do not digest model output or provider/model identity.
    return ExplanationContext(canonical_json(data), content_digest(data))


def load_context(queries, analysis_id, incident_id):
    detail = queries.analysis(analysis_id)
    incident = queries.get(analysis_id, "incidents", incident_id)
    if not (detail.get("grounding") or {}).get("valid"):
        from app.services.queries import QueryError
        raise QueryError(409, "ai_grounding_unavailable")
    chain = queries.chain(analysis_id, incident_id)
    for edge in chain.edges:
        queries.edge(analysis_id, edge.edge_id)
    try:
        return build_context(analysis_id, incident, chain, queries.by_ids(analysis_id, "alerts", incident.alert_ids),
                             queries.by_ids(analysis_id, "entities", incident.entity_ids),
                             queries.by_ids(analysis_id, "correlation_edges", incident.correlation_edge_ids),
                             is_complete=detail["is_complete"])
    except (ValueError, KeyError):
        from app.services.queries import QueryError
        raise QueryError(409, "ai_context_grounding_failed") from None


class ExplanationService:
    def __init__(self, provider=None, *, unavailable_reason="provider_not_configured", cache_size=128):
        self.provider, self.unavailable_reason, self.cache_size = provider, unavailable_reason, cache_size
        self._cache, self._lock = {}, Lock()

    def finish(self, context, base, validated, **state):
        from .report import markdown_report, soc_json_report
        result = GroundedExplanation.model_validate({**base, **validated, "grounding_status": "validated", **state})
        if not result.attack_techniques:
            result.uncertainties.append(Uncertainty(code="insufficient_attack_mapping",
                statement=UNCERTAINTY_TEXT["insufficient_attack_mapping"], object_refs=[result.incident_id]))
        if result.degraded:
            result.uncertainties.append(Uncertainty(code="ai_degraded",
                statement="生成不可用或部分内容未通过验证；正式报告仅包含已验证内容，事实模板不表示 LLM 生成成功。",
                object_refs=[result.incident_id]))
        report = soc_json_report(result, context)
        return GroundedExplanation.model_validate({**result.model_dump(), "report_json": report,
            "report_markdown": markdown_report(result.explanation, soc=report)})

    def degrade(self, context, base, status, detail, generation_status, *, errors=(), rejected=()):
        from .grounding import validate_draft
        metadata = {"provider": "deterministic", "model": "fact-templates", "prompt_version": PROMPT_VERSION}
        validated, failures = validate_draft(context, deterministic_draft(context), metadata)
        if failures:
            raise ValueError("deterministic_fallback_grounding_failed")
        return self.finish(context, base, validated, status=status, detail=detail, degraded=True,
            generation_status=generation_status, result_origin="deterministic",
            validation_errors=list(errors), rejected_claims=list(rejected))

    def explain(self, context):
        data = context.data
        base = {"analysis_id": data["analysis_id"], "incident_id": data["incident"]["incident_id"],
                "input_digest": context.input_digest, "context_status": "context_ready",
                "provider_metadata": None, "explanation": None, "summary": [], "key_findings": [],
                "attack_progression": [], "recommended_actions": [], "validation_errors": [],
                "attack_catalog_version": data["attack_catalog"]["version"],
                "attack_catalog_digest": data["attack_catalog_digest"],
                "attack_mapping_version": data["attack_catalog"]["mapping_version"],
                "uncertainties": [{"code": code, "statement": statement, "object_refs": [data["incident"]["incident_id"]]}
                                  for code, statement in sorted(data["uncertainties"].items())]}
        if self.provider is None:
            return self.degrade(context, base, "unavailable", self.unavailable_reason, "provider_unavailable")
        base["provider_metadata"] = {"provider": self.provider.name, "model": self.provider.model or "unconfigured", "prompt_version": PROMPT_VERSION}
        from .prompts import SYSTEM_PROMPT
        key = (data["analysis_id"], data["incident"]["incident_id"], data["chain_id"], context.input_digest,
               self.provider.cache_identity, PROMPT_VERSION, content_digest(SYSTEM_PROMPT),
               content_digest(ExplanationDraft.model_json_schema()), content_digest(GroundedExplanation.model_json_schema()))
        with self._lock:
            cached = self._cache.get(key)
        if cached is not None:
            return GroundedExplanation.model_validate_json(cached)
        try:
            text = self.provider.explain(context)
        except ProviderError as exc:
            return self.degrade(context, base, "unavailable", exc.code,
                "provider_unavailable" if exc.code == "provider_not_configured" else "provider_failed")
        except Exception:
            return self.degrade(context, base, "unavailable", "provider_error", "provider_failed")
        try:
            # Duplicate JSON keys must not smuggle a second interpretation.
            def unique_pairs(pairs):
                obj = {}
                for name, value in pairs:
                    if name in obj:
                        raise ValueError("duplicate_json_key")
                    obj[name] = value
                return obj
            def reject_constant(value):
                raise ValueError("invalid_json_number")
            if not isinstance(text, str) or len(text.encode("utf-8")) > 2097152:
                raise ValueError("invalid_response")
            from hashlib import sha256
            base["generation_digest"] = sha256(text.encode("utf-8")).hexdigest()
            parsed = json.loads(text, object_pairs_hook=unique_pairs, parse_constant=reject_constant)
            draft = ExplanationDraft.model_validate_json(json.dumps(parsed, ensure_ascii=False, allow_nan=False))
        except (ValueError, TypeError, ValidationError, RecursionError):
            return self.degrade(context, base, "validation_failed", "provider_invalid_draft", "parsing_failed",
                                errors=["draft_schema_invalid"])
        from .grounding import validate_draft
        try:
            validated, errors = validate_draft(context, draft, base["provider_metadata"])
        except (ValueError, KeyError, TypeError, RecursionError):
            return self.degrade(context, base, "validation_failed", "grounding_validation_failed", "grounding_rejected",
                                errors=["grounding_validator_failed"])
        if errors:
            return self.degrade(context, base, "validation_failed", "grounding_validation_failed", "grounding_rejected", errors=errors)
        rejected = validated["rejected_claims"]
        codes = sorted({code for r in rejected for code in r["validation_errors"]})
        if rejected and not any(validated[k] for k in ("summary", "key_findings", "attack_progression")):
            return self.degrade(context, base, "validation_failed", "grounding_validation_failed", "grounding_rejected",
                                errors=codes, rejected=rejected)
        origin = "llm"
        if not validated["summary"]:
            # Keep accepted claims while replacing a rejected summary with a
            # separately validated, deterministic summary of this same context.
            fallback, _ = validate_draft(context, deterministic_draft(context), base["provider_metadata"])
            validated["summary"] = fallback["summary"]
            explanation = validated["explanation"].model_dump(mode="json")
            explanation["claims"].extend(c.model_dump(mode="json") for c in fallback["explanation"].claims if c.section.value == "summary")
            explanation["explanation_id"] = id_for("AIExplanation", explanation)
            validated["explanation"] = AIExplanation.model_validate(explanation)
            origin = "mixed"
        partial = bool(rejected or validated["rejected_mappings"])
        result = self.finish(context, base, validated, status="available",
            detail="grounding_partial_rejection" if partial else "grounded_explanation_ready",
            degraded=partial, generation_status="partially_rejected" if partial else "succeeded",
            result_origin=origin, validation_errors=codes)
        # Failure/partial responses are retried, so recovery does not require
        # waiting for cache eviction. Only fully accepted results are cached.
        if self.cache_size > 0 and not result.degraded:
            with self._lock:
                if len(self._cache) >= self.cache_size:
                    self._cache.pop(next(iter(self._cache)))
                self._cache[key] = result.model_dump_json()
        return result


def deterministic_draft(context):
    """Read-only fact templates; never select ATT&CK candidates on failure."""
    from .grounding import make_finding
    data = context.data
    summary = make_finding(data, [{"subject_type": "alert", "subject_id": aid, "field": field, "value": alert[field]}
        for aid, alert in data["facts"]["alerts"].items() for field in ("timestamp", "source_type", "category")])
    return ExplanationDraft.model_validate({"incident_id": data["incident"]["incident_id"], "summary": [summary],
        "key_findings": data["fact_options"]["findings"], "attack_progression": data["fact_options"]["progression"],
        "uncertainties": sorted(data["uncertainties"]), "attack_techniques": [],
        "recommended_actions": [{"action": "verify_alert", "recommendation": ACTION_TEMPLATES["verify_alert"],
            "reason": RECOMMENDATION_REASON, "related_object_refs": data["incident"]["alert_ids"]}]})
