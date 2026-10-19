"""Reports contain validated claims only, with no provider prose bypass."""

import html

from app.models.enums import GroundingStatus


def json_report(explanation):
    if explanation.grounding_status != GroundingStatus.VALIDATED or any(
            c.grounding_status != GroundingStatus.VALIDATED for c in explanation.claims):
        raise ValueError("report_requires_validated_claims")
    return explanation.model_dump(mode="json")


def soc_json_report(result, context):
    """Official export whitelist, excluding generation diagnostics and drafts."""
    data = json_report(result.explanation)
    projected = context.data
    if (data["analysis_id"] != projected["analysis_id"] or data["incident_id"] != projected["incident"]["incident_id"]
            or data["chain_id"] != projected["chain_id"] or data["input_digest"] != context.input_digest):
        raise ValueError("report_context_mismatch")
    return {**data, "summary": [v.model_dump(mode="json") for v in result.summary],
        "observed_facts": [v.model_dump(mode="json") for v in [*result.key_findings, *result.assessment]],
        "attack_path": [v.model_dump(mode="json") for v in result.attack_progression],
        "attack_techniques": [v.model_dump(mode="json") for v in result.attack_techniques],
        "key_entities": [v.model_dump(mode="json") for v in result.key_entities],
        "risk": result.risk.model_dump(mode="json"),
        "recommended_actions": [v.model_dump(mode="json") for v in result.recommended_actions],
        "evidence_refs": projected["evidence_refs"],
        "limitations": [u.model_dump(mode="json") for u in result.uncertainties],
        "degraded": result.degraded, "generation_status": result.generation_status, "result_origin": result.result_origin,
        "has_directed_path": bool(projected["ordered_edge_ids"])}


def literal(text):
    text = html.escape(text)
    for symbol in ("\\", "`", "*", "_", "{", "}", "[", "]", "(", ")", "#", "+", "-", "!", "|"):
        text = text.replace(symbol, "\\" + symbol)
    return text


def markdown_report(explanation, *, soc=None):
    data = json_report(explanation)
    labels = {"summary": "Incident Summary", "attack_path": "Attack Progression",
              "attack_mapping": "ATT&CK Techniques", "risk": "SOC Assessment", "recommendations": "Recommendations / Advisory"}
    lines = ["# Incident Explanation", "", "Analysis: " + data["analysis_id"],
             "Incident: " + data["incident_id"], "Chain: " + data["chain_id"], ""]
    if soc is not None:
        lines += ["Generation: " + soc["generation_status"], "Result origin: " + soc["result_origin"], ""]
    for section, label in labels.items():
        lines += ["## " + label, ""]
        if section == "attack_path" and soc is not None and not soc["has_directed_path"]:
            lines += ["当前快照没有得到证据支持的多阶段有向攻击链，不补充攻击步骤。", ""]
        for claim in data["claims"]:
            if claim["section"] != section:
                continue
            # Escape device/entity strings as literal text, not active Markdown
            # or HTML (e.g. account names supplied by an upstream alert).
            text = literal(claim["text"])
            lines += [text, "", "Claim: " + claim["claim_id"],
                      "Alerts: " + ", ".join(claim["alert_ids"]),
                      "Nodes: " + ", ".join(claim["node_ids"]),
                      "Edges: " + ", ".join(claim["edge_ids"]), ""]
    if soc is not None:
        lines += ["## Risk Assessment", "", literal(soc["risk"]["statement"]),
                  "Observed severity: " + literal(soc["risk"]["observed_severity"]), "",
                  "## Evidence References", ""]
        for ref in soc["evidence_refs"]:
            lines += [literal(ref["alert_id"] + " " + ref["pointer"] + " (" + ref["side"] + ")"), ""]
        lines += ["## Limitations / Uncertainty", ""]
        for item in soc["limitations"]:
            lines += [literal(item["statement"]), ""]
    return "\n".join(lines)
