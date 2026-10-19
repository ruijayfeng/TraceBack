"""DATA_CONTRACT §2 canonical serialization and all thirteen v1 identities.

The envelope kind is the contract's model name (e.g. CanonicalAlert). Numbers
in content digests are decimal JSON numbers; nonintegral identity numbers use
the contract's $decimal tag. Ordinary JSON arrays always retain their order.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from hashlib import sha256
import json
import re
import unicodedata
from typing import Any, Mapping


PREFIXES = {
    "CanonicalAlert": "alt", "Entity": "ent", "DedupeGroup": "dup",
    "CorrelationEdge": "cor", "Incident": "inc", "ChainNode": "nod",
    "ChainEdge": "che", "AttackChain": "chn", "Reason": "rsn",
    "AIClaim": "clm", "AIExplanation": "aix", "AnalysisRecord": "ana",
}
ID_FIELDS = {kind: field for kind, field in zip(PREFIXES, (
    "alert_id", "entity_id", "group_id", "edge_id", "incident_id", "node_id",
    "edge_id", "chain_id", "reason_id", "claim_id", "explanation_id", "analysis_id",
), strict=True)}


def nfc(value: str) -> str:
    value.encode("utf-8")  # Reject lone surrogates, which are not UTF-8 strings.
    return unicodedata.normalize("NFC", value)


def utc_text(value: str | datetime) -> str:
    """Timezone-aware RFC3339 → UTC; truncate sub-microsecond input."""
    if type(value) is str:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", value):
            raise ValueError("timestamp must be timezone-aware RFC3339")
        offset = re.search(r"[+-](\d{2}):(\d{2})$", value)
        if offset and (int(offset[1]) > 23 or int(offset[2]) > 59):
            raise ValueError("invalid RFC3339 timezone offset")
        value = re.sub(r"(\.\d{6})\d+", r"\1", value)
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("invalid RFC3339 timestamp") from exc
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def decimal_text(value: int | float | Decimal) -> str:
    d = Decimal(str(value))
    if not d.is_finite():
        raise ValueError("non-finite JSON number")
    if d.is_zero():
        return "0"
    # No Decimal.normalize(): it can round under the process Decimal context.
    text = format(d, "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


def normalize_json(value: Any, *, identity_numbers: bool = False) -> Any:
    if isinstance(value, Enum):
        value = value.value
    if value is None or type(value) is bool or type(value) is int:
        return value
    if type(value) is str:
        return nfc(value)
    if type(value) in (float, Decimal):
        text = decimal_text(value)
        d = Decimal(text)
        if identity_numbers:
            return int(d) if d == d.to_integral_value() else {"$decimal": text}
        return d
    if type(value) is list:
        return [normalize_json(v, identity_numbers=identity_numbers) for v in value]
    if type(value) is dict:
        result = {}
        for key, child in value.items():
            if type(key) is not str:
                raise ValueError("JSON object keys must be strings")
            key = nfc(key)
            if key in result:
                raise ValueError("JSON keys collide after NFC normalization")
            result[key] = normalize_json(child, identity_numbers=identity_numbers)
        return result
    raise ValueError(f"not a JSON value: {type(value).__name__}")


def _encode(value: Any) -> str:
    if type(value) is dict:
        return "{" + ",".join(_encode(k) + ":" + _encode(value[k]) for k in sorted(value)) + "}"
    if type(value) is list:
        return "[" + ",".join(_encode(v) for v in value) + "]"
    if type(value) is Decimal:
        return decimal_text(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def canonical_json(value: Any, *, identity_numbers: bool = False) -> str:
    return _encode(normalize_json(value, identity_numbers=identity_numbers))


def canonical_model_json(data: dict) -> str:
    """Canonical persisted object, preserving the contract's exact raw text.

    Generic JSON/identity NFC normalization must not rewrite a text raw_alert,
    whose fingerprint hashes the exact original UTF-8 text.
    """
    normalized = normalize_json(data)
    if type(data.get("raw_alert")) is str:
        normalized["raw_alert"] = data["raw_alert"]
    return _encode(normalized)


def content_digest(value: Any) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def raw_fingerprint(raw_alert: dict | str) -> str:
    if type(raw_alert) is str:
        return sha256(raw_alert.encode("utf-8")).hexdigest()  # Exact text, including Unicode form.
    if type(raw_alert) is not dict:
        raise ValueError("raw_alert must be an object or text")
    return content_digest(raw_alert)


def sorted_set(values: list) -> list:
    """NFC-normalize and deduplicate a declared scalar set."""
    return sorted({nfc(v.value if isinstance(v, Enum) else v) for v in values})


def pointer_set(values: list[dict]) -> list[dict]:
    normalized = [normalize_json(v) for v in values]
    return list({(v["alert_id"], v["pointer"], v["side"]): v for v in
                 sorted(normalized, key=lambda v: (v["alert_id"], v["pointer"], v["side"]))}.values())


def normalize_params(code: str, params: dict) -> dict:
    # Schema validation lives in models/reasons.py; this helper only canonicalizes
    # the contract's declared arrays and never guesses arbitrary array semantics.
    result = dict(params)
    fields = {
        "shared_entity": ("roles",),
        "source_complement": ("source_types", "sensor_names", "independence_rule_ids"),
    }.get(code, ())
    for field in fields:
        if field in result:
            result[field] = sorted_set(result[field])
    if code in ("explicit_relation", "source_complement") and "raw_pointers" in result:
        result["raw_pointers"] = pointer_set(result["raw_pointers"])
    if code == "clustering_guard" and "component_sizes" in result:
        result["component_sizes"] = sorted(result["component_sizes"])
    # Keep JSON numbers in persistence; only identity encoding adds decimal tags.
    return json.loads(canonical_json(result))


def normalize_propositions(values: list[dict]) -> list[dict]:
    result = {}
    for original in values:
        value = json.loads(canonical_json(original))
        # Only snapshot fields explicitly declared as scalar sets are normalized.
        if value["field"] in ("entity_ids", "alert_ids", "correlation_edge_ids"):
            if type(value["value"]) is list:
                value["value"] = sorted_set(value["value"])
        key = (value["subject_type"], value["subject_id"], value["field"],
               canonical_json(value["value"], identity_numbers=True))
        result[key] = value
    return [result[key] for key in sorted(result)]


def identity_for(kind: str, data: Mapping | Any) -> dict:
    """Extract exactly the contract identity; derived scores are not identity."""
    if hasattr(data, "model_dump"):
        data = data.model_dump(mode="json")
    if kind == "CanonicalAlert":
        return {"source_namespace": data["source_namespace"],
                "origin_namespace": data.get("origin_namespace"),
                "source_record_id": data.get("source_record_id"),
                "timestamp": utc_text(data["timestamp"]), "raw_fingerprint": data["raw_fingerprint"]}
    if kind == "Entity":
        return {key: data[key] for key in ("type", "scope", "value")}
    if kind in ("DedupeGroup", "Incident"):
        return {"alert_ids": sorted_set(data["alert_ids"])}
    if kind == "CorrelationEdge":
        return {"alert_ids": sorted_set([data["source_alert_id"], data["target_alert_id"]])}
    if kind == "ChainNode":
        return {"incident_id": data["incident_id"], "category": data["category"],
                "alert_ids": sorted_set(data["alert_ids"])}
    if kind == "ChainEdge":
        return {key: data[key] for key in ("incident_id", "source_node_id", "target_node_id", "relation_type")}
    if kind == "AttackChain":
        return {"incident_id": data["incident_id"],
                "node_ids": sorted_set([v["node_id"] for v in data["nodes"]]),
                "edge_ids": sorted_set([v["edge_id"] for v in data.get("edges", [])])}
    if kind == "Reason":
        return {"code": data["code"], "alert_ids": sorted_set(data["alert_ids"]),
                "entity_ids": sorted_set(data.get("entity_ids", [])),
                "params": normalize_params(data["code"], data["params"])}
    if kind == "AIClaim":
        result = {key: data[key] for key in ("kind", "section", "text")}
        result.update({key: sorted_set(data.get(key, [])) for key in ("node_ids", "edge_ids", "alert_ids")})
        result.update(propositions=normalize_propositions(data.get("propositions", [])),
                      attack_mapping=data.get("attack_mapping"))
        return result
    if kind == "AIExplanation":
        result = {key: data[key] for key in ("analysis_id", "incident_id", "chain_id", "input_digest",
                                           "provider", "model", "prompt_version")}
        result["claim_ids"] = sorted_set([v["claim_id"] for v in data["claims"]])
        return result
    if kind == "AnalysisRecord":
        return {"alert_ids": sorted_set(data["input_alert_ids"]), "config_hash": data["config_hash"],
                "algorithm_version": data["algorithm_version"], "schema_version": data.get("schema_version", "1.0")}
    raise ValueError(f"unknown identity kind: {kind}")


def stable_id(kind: str, identity: dict) -> str:
    if kind not in PREFIXES:
        raise ValueError(f"unknown identity kind: {kind}")
    body = canonical_json({"id_version": "v1", "kind": kind, "identity": identity}, identity_numbers=True)
    return PREFIXES[kind] + "_" + sha256(body.encode("utf-8")).hexdigest()


def id_for(kind: str, data: Mapping | Any) -> str:
    return stable_id(kind, identity_for(kind, data))


class IdentityRegistry:
    """In-memory collision check with explicit analysis keys, not a storage layer."""

    def __init__(self) -> None:
        self._identities: dict[tuple[str, str], str] = {}
        self._object_identities: dict[str, str] = {}

    def register(self, analysis_id: str, object_id: str, kind: str, data: Mapping | Any) -> tuple[str, str]:
        if not re.fullmatch(r"ana_[0-9a-f]{64}", analysis_id):
            raise ValueError("invalid analysis ID")
        if kind not in PREFIXES or not re.fullmatch(PREFIXES[kind] + r"_[0-9a-f]{64}", object_id):
            raise ValueError("invalid object ID")
        key = (analysis_id, object_id)
        identity = canonical_json(identity_for(kind, data), identity_numbers=True)
        if object_id in self._object_identities and self._object_identities[object_id] != identity:
            raise ValueError("same ID has conflicting identity")
        if object_id != id_for(kind, data):
            raise ValueError("object ID conflicts with its supplied identity")
        self._identities[key] = identity
        self._object_identities[object_id] = identity
        return key
