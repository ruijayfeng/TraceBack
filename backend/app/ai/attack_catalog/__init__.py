"""Small, controlled local registry. No network or production discovery access.

Catalog membership is distinct from mapping support: entries without a rule
are recognized but fail closed until the whitelist can prove their semantics.
Names/tactics/parent links were checked against the recorded MITRE source URLs.
"""

import json
from pathlib import Path
import shlex
from typing import Annotated

from pydantic import Field, model_validator

from app.models.base import StrictModel, Text
from app.utils.stable_id import content_digest


class Technique(StrictModel):
    technique_id: Annotated[str, Field(pattern=r"^T[0-9]{4}(?:\.[0-9]{3})?$")]
    technique_name: Text
    tactics: Annotated[list[Text], Field(min_length=1)]
    parent_id: Text | None
    source_url: Text
    rule: Text | None


class MappingRule(StrictModel):
    categories: Annotated[list[Text], Field(min_length=1)]
    executables: Annotated[list[Text], Field(min_length=1)]


class AttackCatalog(StrictModel):
    version: Text
    mapping_version: Text
    techniques: Annotated[list[Technique], Field(min_length=1)]
    rules: dict[Text, MappingRule]

    @model_validator(mode="after")
    def integrity(self):
        entries = {t.technique_id: t for t in self.techniques}
        if len(entries) != len(self.techniques):
            raise ValueError("duplicate_technique_id")
        for t in self.techniques:
            expected = t.technique_id.split(".")[0] if "." in t.technique_id else None
            if t.parent_id != expected or (expected and (expected not in entries or entries[expected].parent_id)):
                raise ValueError("invalid_subtechnique_parent")
            if len(set(t.tactics)) != len(t.tactics) or not set(t.tactics) <= {"Execution", "Initial Access", "Lateral Movement"}:
                raise ValueError("invalid_catalog_tactic")
            if expected and not set(t.tactics) <= set(entries[expected].tactics):
                raise ValueError("invalid_subtechnique_tactic")
            if t.rule is not None and t.rule not in self.rules:
                raise ValueError("missing_mapping_rule")
        return self

    @property
    def snapshot(self):
        data = self.model_dump(mode="json")
        data["techniques"] = sorted(data["techniques"], key=lambda t: t["technique_id"])
        for t in data["techniques"]:
            t["tactics"] = sorted(t["tactics"])
        for r in data["rules"].values():
            r["categories"], r["executables"] = sorted(r["categories"]), sorted(r["executables"])
        return data

    @property
    def digest(self):
        return content_digest(self.snapshot)

    def support(self, technique, alert, entities):
        rule = self.rules.get(technique.rule)
        if rule is None or alert["category"] not in rule.categories:
            return False
        # Only current process/command occurrences count; a parent interpreter
        # or an unrelated entity elsewhere in the Incident does not suffice.
        for occurrence in alert["entity_occurrences"]:
            entity = entities[occurrence["entity_id"]]
            value = entity["value"]
            if occurrence["role"] == "process" and entity["type"] == "PROCESS":
                try:
                    instance = json.loads(value)
                except ValueError:
                    instance = None
                if isinstance(instance, dict):
                    value = instance.get("executable") or instance.get("name") or ""
                if value in rule.executables:
                    return True
            if occurrence["role"] == "command" and entity["type"] == "COMMAND":
                try:
                    words = shlex.split(value)
                except ValueError:
                    words = []
                if words and words[0] in rule.executables:
                    return True
        return False


def load_catalog():
    # Fixed package resource only: no user supplied paths or runtime fetch.
    return AttackCatalog.model_validate_json(Path(__file__).with_name("registry.json").read_text(encoding="utf-8"))
