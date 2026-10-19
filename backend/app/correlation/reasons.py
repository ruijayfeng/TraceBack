"""Contract-shaped deterministic reasons; no free-form AI text."""

from app.models import Reason
from app.utils.stable_id import id_for


MESSAGES = {
    "time_gap": lambda p: f"告警时间差 {p['gap_seconds']} 秒，半衰期 {p['half_life_seconds']} 秒",
    "shared_entity": lambda p: f"共享 {p['entity_type']} 实体；稀有度 {p['rarity']}，实体贡献 {p['contribution']}",
    "explicit_relation": lambda p: f"结构化告警字段支持 {p['relation_type']} 关系",
    "behavior_transition": lambda p: f"配置行为转换 {p['from_category']} → {p['to_category']}，兼容值 {p['compatibility']}",
    "source_complement": lambda p: f"来源状态 {p['source_independence']}；判定依据 {p['rule_id']}",
    "conflict": lambda p: f"命中冲突规则 {p['rule_id']}，惩罚强度 {p['penalty']}",
    "duplicate": lambda p: f"声明的重复特征相似值 {p['similarity']}；规则 {p['rule_id']}",
}


def make_reason(code, alert_ids, params, entity_ids=(), context=None):
    data = {"code": code, "message": MESSAGES[code](params), "alert_ids": sorted(alert_ids),
            "entity_ids": sorted(set(entity_ids)), "params": params}
    data["reason_id"] = id_for("Reason", data)
    return Reason.model_validate(data, context=context)


def bound_fields(alert, names, side="shared"):
    return [{"alert_id": alert.alert_id, "pointer": alert.field_provenance[name].raw_pointer, "side": side}
            for name in names if name in alert.field_provenance and getattr(alert, name) is not None]
