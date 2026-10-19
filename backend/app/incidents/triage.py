"""Availability-aware single alert SOC priority; never fed into correlation."""

from collections import defaultdict
import math

from app.models import Incident
from app.models.triage import SingleAlertTriage


def triage_singletons(incidents, index, config, correlation_summary, *, search_complete, rule_counts=None):
    cfg = config.algorithm.single_alert_triage
    if cfg is None:
        return incidents
    rule_groups = defaultdict(set)
    if rule_counts is None:
        for aid, a in index.alerts.items():
            if a.rule_id is not None:
                rule_groups[(a.source_namespace, a.rule_id)].add(index.owner[aid])
    diagnostics = correlation_summary.get("alert_correlation_diagnostics", {})
    result = []
    for incident in incidents:
        if len(incident.alert_ids) != 1:
            result.append(incident)
            continue
        a = index.alerts[incident.alert_ids[0]]
        reason_rows, unavailable = [], []
        for field in ("severity", "category", "rarity"):
            basis = "rule_id" if field == "rarity" else field
            value = getattr(a, basis)
            value = value.value if field in {"severity", "category"} else value
            if value is None or value == "unknown" or basis not in a.field_provenance:
                unavailable.append(field)
                continue
            if field == "severity":
                strength = cfg.severity_scores[value]
                message = f"设备告警等级为 {value}；风险贡献来自配置映射，未确认真实入侵"
            elif field == "category":
                strength = cfg.category_scores[value]
                message = f"已映射告警类别为 {value}；类别风险由配置定义"
            else:
                df = rule_counts[(a.source_namespace, a.rule_id)] if rule_counts is not None else len(rule_groups[(a.source_namespace, a.rule_id)])
                n, smoothing = index.N, cfg.rarity_smoothing
                strength = max(0, min(1, math.log((n+smoothing)/(df+smoothing))/math.log(n+smoothing)))
                value = {"rule_id": a.rule_id, "source_namespace": a.source_namespace, "df": df, "N": n}
                message = f"本源规则在 {df}/{n} 个事实组中出现；稀有不等于恶意"
            weight = cfg.weights[field]
            ref = {"alert_id": a.alert_id, "pointer": a.field_provenance[basis].raw_pointer, "side": "shared"}
            reason_rows.append(dict(field=field, value=value, strength=round(strength, 6), weight=weight,
                contribution=weight*strength, message=message, evidence_refs=[ref]))
        aw, mw = sum(r["weight"] for r in reason_rows), sum(r["contribution"] for r in reason_rows)
        score = mw/aw if aw else 0
        if reason_rows and all(r["field"] == "rarity" for r in reason_rows):
            score = min(score, cfg.rarity_only_cap)
        level = "unknown" if not reason_rows else next((level for level in ("critical", "high", "medium")
                                                       if score >= cfg.risk_thresholds[level]), "low")
        d = diagnostics.get(index.owner[a.alert_id], {})
        candidate_count, formal = d.get("candidate_count", 0), d.get("formal_edge_count", 0)
        text = ("存在正式无向关联，但受控聚类未将其并入其他事件" if formal else
                "局部准入策略未发现合法非时间候选" if not candidate_count else
                "已准入候选未同时满足关联阈值、证据充分性和保护规则")
        if not search_complete:
            text += "；分析不完整，未执行候选不代表不相关"
        text += "。检索限定于配置窗口和候选准入策略；没有证明关联不等于没有攻击。"
        refs = { (p["alert_id"], p["pointer"], p["side"]): p for r in reason_rows for p in r["evidence_refs"] }
        triage = SingleAlertTriage.model_validate(dict(alert_id=a.alert_id,
            description=f"{a.source_type.value} / {a.signature or a.alert_type or a.rule_id or 'unknown'} / {a.category.value}",
            single_alert_risk_score=round(score, 6), risk_level=level,
            recommended_priority={"unknown":"UNRATED", "low":"P4", "medium":"P3", "high":"P2", "critical":"P1"}[level],
            available_weight=aw, matched_weight=mw, rarity_only_cap=cfg.rarity_only_cap,
            risk_reasons=reason_rows, evidence_refs=[refs[k] for k in sorted(refs)], unavailable_evidence=unavailable,
            candidate_count=candidate_count, gate_passed_count=d.get("gate_passed_count", 0), formal_edge_count=formal,
            rejection_counts=d.get("decisions", {}), correlation_diagnostic=text, search_complete=search_complete))
        for ref in triage.evidence_refs:
            ref.resolve(index.alerts)
        data = incident.model_dump()
        data["single_alert_triage"] = triage.model_dump()
        data["summary"] = f"单告警 / 风险 {level.upper()} / 优先级 {triage.recommended_priority}。{text}"
        result.append(Incident.model_validate(data))
    return result
