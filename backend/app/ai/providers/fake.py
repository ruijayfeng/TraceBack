"""Explicit offline test provider. Production never selects this fallback."""

from copy import deepcopy
import json

from app.ai.grounding import make_finding
from app.ai.prompts import ACTION_TEMPLATES, RECOMMENDATION_REASON
from app.ai.provider import LLMProvider, ProviderError


def finding(context, propositions):
    return make_finding(context.data, propositions)


def valid_draft(context):
    data = context.data
    alerts = data["facts"]["alerts"]
    # Summarize the entire Incident's observed alert facts; no invented activity.
    summary = finding(context, [{"subject_type": "alert", "subject_id": aid, "field": field, "value": alert[field]}
                               for aid, alert in alerts.items() for field in ("timestamp", "source_type", "category")])
    aid = max(alerts, key=lambda key: ({"unknown": 0, "informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}[alerts[key]["severity"]], key))
    risk = finding(context, [{"subject_type": "alert", "subject_id": aid, "field": field, "value": alerts[aid][field]}
                            for field in ("severity", "entity_occurrences")])
    progression = []
    for step, eid in enumerate(data["ordered_edge_ids"], 1):
        edge = data["facts"]["edges"][eid]
        progression.append({**finding(context, [{"subject_type": "chain_edge", "subject_id": eid, "field": field,
                             "value": edge[field]} for field in ("source_node_id", "target_node_id", "relation_type", "reasons", "score_breakdown")]), "step": step})
    return {"incident_id": data["incident"]["incident_id"], "summary": [summary],
            "key_findings": [risk, *data["fact_options"]["mapping_facts"]],
            "attack_techniques": data["attack_mapping_options"],
            "attack_progression": progression, "uncertainties": sorted(data["uncertainties"]),
            "recommended_actions": [{"action": "verify_alert", "recommendation": ACTION_TEMPLATES["verify_alert"],
                                      "reason": RECOMMENDATION_REASON, "related_object_refs": [aid]}]}


class FakeProvider(LLMProvider):
    name, model = "fake", "offline-fixture"

    def __init__(self, mode="valid", transform=None):
        self.mode, self.transform, self.calls = mode, transform, 0

    @property
    def cache_identity(self):
        return (*super().cache_identity, self.mode, self.transform)

    def explain(self, context):
        self.calls += 1
        if self.mode == "timeout":
            raise ProviderError("provider_timeout")
        if self.mode == "invalid_json":
            return "{broken"
        if self.mode == "empty":
            return ""
        draft = deepcopy(valid_draft(context))
        if self.mode == "invalid_evidence":
            draft["summary"][0]["evidence_refs"][0]["pointer"] = "/nonexistent_evidence"
        elif self.mode == "invalid_node":
            draft["summary"][0]["node_refs"] = ["nod_" + "f" * 64]
        elif self.mode == "missing_field":
            del draft["summary"]
        elif self.mode.startswith("mapping_"):
            if not draft["attack_techniques"]:
                node = next(iter(context.data["facts"]["nodes"]))
                draft["attack_techniques"] = [{"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter",
                    "tactic": "Execution", "parent_id": None, "confidence": "tentative", "reason": "unsupported",
                    "catalog_version": context.data["attack_catalog"]["version"], "supporting_fact_ids": ["clm_" + "f" * 64],
                    **{k: draft["summary"][0][k] for k in ("object_refs", "edge_refs", "alert_refs", "evidence_refs")},
                    "node_refs": [node]}]
            mapping = draft["attack_techniques"][0]
            if self.mode == "mapping_unknown":
                mapping["technique_id"] = "T9999"
            elif self.mode == "mapping_name":
                mapping["technique_name"] = "Credential Dumping"
            elif self.mode == "mapping_fact":
                mapping["supporting_fact_ids"] = ["clm_" + "f" * 64]
            elif self.mode == "mapping_evidence":
                mapping["evidence_refs"][0]["pointer"] = "/nonexistent"
            elif self.mode == "mapping_entity":
                mapping["reason"] += " host=unobserved-host account=unobserved-admin session=unobserved-session 203.0.113.99"
            elif self.mode == "mapping_unsupported":
                mapping.update(technique_id="T1021.002", technique_name="SMB/Windows Admin Shares",
                               tactic="Lateral Movement", parent_id="T1021")
        if self.transform:
            self.transform(draft)
        return json.dumps(draft, ensure_ascii=False)
