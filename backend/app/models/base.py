"""Shared strict primitives and structural reference helpers, DATA_CONTRACT §1."""

from __future__ import annotations

from decimal import Decimal
import math
import re
from typing import Annotated, Any, Literal

from pydantic import (AfterValidator, BaseModel, BeforeValidator, ConfigDict,
                      Field, PlainSerializer, ValidationInfo, model_validator)

from app.utils.stable_id import ID_FIELDS, canonical_json, canonical_model_json, id_for, nfc, utc_text


def finite_number(value):
    try:
        valid = type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        valid = False
    if not valid:
        raise ValueError("requires a finite JSON number, not a boolean or numeric string")
    return value


def score_precision(value):
    if Decimal(str(value)) != Decimal(str(value)).quantize(Decimal("0.000001")):
        raise ValueError("Score allows at most six decimal places")
    return value


def json_value(value):
    def check(v):
        if v is None or type(v) in (bool, int, str):
            if type(v) is str:
                nfc(v)
            return
        if type(v) is float:
            finite_number(v)
            return
        if type(v) is list:
            for item in v:
                check(item)
            return
        if type(v) is dict:
            for key, item in v.items():
                if type(key) is not str:
                    raise ValueError("JSON keys must be strings")
                nfc(key)
                check(item)
            return
        raise ValueError("requires a JSON value, not a runtime object")
    check(value)
    # Also reject ambiguous keys after NFC while preserving original raw fields.
    canonical_json(value)
    return value


def pointer_text(value):
    if value != "" and (not value.startswith("/") or re.search(r"~(?![01])", value)):
        raise ValueError("requires an RFC6901 JSON Pointer (or empty root pointer)")
    return value


Text = Annotated[str, Field(min_length=1), AfterValidator(nfc)]
Number = Annotated[float, BeforeValidator(finite_number)]
NonNegative = Annotated[Number, Field(ge=0)]
Positive = Annotated[Number, Field(gt=0)]
Score = Annotated[Number, Field(ge=0, le=1), AfterValidator(score_precision)]
OutputNumber = Annotated[Number, PlainSerializer(lambda v: round(v, 6), when_used="json")]
NonNegativeInt = Annotated[int, Field(ge=0)]
PositiveInt = Annotated[int, Field(gt=0)]
UTCDateTime = Annotated[str, BeforeValidator(utc_text)]
Json = Annotated[Any, BeforeValidator(json_value)]
Pointer = Annotated[str, AfterValidator(pointer_text)]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


def id_type(prefix):
    return Annotated[str, Field(pattern=rf"^{prefix}_[0-9a-f]{{64}}$")]


AlertID, EntityID, DedupeID, CorrelationID, IncidentID, NodeID, ChainEdgeID, ChainID, ReasonID, ClaimID, ExplanationID, AnalysisID = (
    id_type(prefix) for prefix in ("alt", "ent", "dup", "cor", "inc", "nod", "che", "chn", "rsn", "clm", "aix", "ana")
)


def unique_ids(values):
    if len(values) != len(set(values)):
        raise ValueError("ID arrays cannot contain duplicates")
    return sorted(values)


def ids(item):
    return Annotated[list[item], AfterValidator(unique_ids)]


def resolve_pointer(raw, pointer: str):
    """Resolve one already bound raw_alert only; never search another record."""
    pointer_text(pointer)
    if pointer == "":
        return raw
    if type(raw) is str:
        raise ValueError("text raw_alert only supports the root pointer")
    value = raw
    for part in pointer[1:].split("/"):
        key = part.replace("~1", "/").replace("~0", "~")
        if type(value) is dict and key in value:
            value = value[key]
        elif type(value) is dict:
            # Identity/persistence NFC must still resolve a preserved raw key.
            # json_value() rejects NFC key collisions, so this lookup is unique.
            matches = [original for original in value if nfc(original) == nfc(key)]
            if len(matches) != 1:
                raise ValueError("JSON Pointer does not resolve in the bound raw_alert")
            value = value[matches[0]]
        elif type(value) is list and re.fullmatch(r"0|[1-9][0-9]*", key) and int(key) < len(value):
            value = value[int(key)]
        else:
            raise ValueError("JSON Pointer does not resolve in the bound raw_alert")
    return value


def check_evidence(pointers, allowed_alert_ids, info: ValidationInfo | None = None):
    for pointer in pointers:
        if pointer.alert_id not in allowed_alert_ids:
            raise ValueError("EvidencePointer alert_id is outside its owning references")
        if info and info.context and "alerts" in info.context:
            alerts = info.context["alerts"]
            if pointer.alert_id not in alerts:
                raise ValueError("EvidencePointer alert is absent from the supplied snapshot")
            alert = alerts[pointer.alert_id]
            raw = alert.raw_alert if hasattr(alert, "raw_alert") else alert["raw_alert"]
            resolve_pointer(raw, pointer.pointer)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True,
                              validate_default=True, revalidate_instances="always", allow_inf_nan=False)

    @model_validator(mode="before")
    @classmethod
    def unambiguous_keys(cls, value):
        # Pydantic dict[Text, ...] would otherwise silently fold NFC-equivalent
        # keys. Check before any field/key normalization loses that distinction.
        def check(item):
            if type(item) is dict:
                keys = set()
                for key, child in item.items():
                    if type(key) is not str:
                        raise ValueError("model/JSON object keys must be strings")
                    normalized = nfc(key)
                    if normalized in keys:
                        raise ValueError("object keys collide after NFC normalization")
                    keys.add(normalized)
                    check(child)
            elif type(item) is list:
                for child in item:
                    check(child)
        check(value)
        return value

    def canonical_json(self) -> str:
        return canonical_model_json(self.model_dump(mode="json"))


class DomainModel(StrictModel):
    schema_version: Literal["1.0"] = "1.0"

    @model_validator(mode="after")
    def identity_matches(self):
        kind = type(self).__name__
        if kind in ID_FIELDS and getattr(self, ID_FIELDS[kind]) != id_for(kind, self):
            raise ValueError(f"{ID_FIELDS[kind]} does not match its v1 identity")
        return self


def sorted_objects(values, key):
    result = {}
    for value in values:
        object_id = getattr(value, key)
        if object_id in result and result[object_id].canonical_json() != value.canonical_json():
            raise ValueError("same ID has conflicting object content")
        result[object_id] = value
    return [result[k] for k in sorted(result)]


def check_interval(start_time, end_time):
    if start_time > end_time:
        raise ValueError("start_time must be <= end_time")
