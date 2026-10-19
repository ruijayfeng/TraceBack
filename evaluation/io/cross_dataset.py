"""Evaluation-only readiness, source declarations, and immutable file bindings."""

import copy
import json
from pathlib import Path

import yaml

from app.adapters import AdapterSettings, AMinerAdapter, WazuhAdapter
from app.config import load_config
from app.services.storage import file_digest
from app.utils.stable_id import content_digest


ADAPTERS = {"wazuh": WazuhAdapter, "aminer": AMinerAdapter}


def core_parameters(config):
    """Source parsing/mapping may vary; every algorithm parameter must match."""
    value = copy.deepcopy(config.algorithm.model_dump(mode="json"))
    for section, keys in {
        "normalization": ("source_timezones", "host_aliases", "category_mapping_files", "severity_mapping_files"),
        "duplicate": ("payload_mapping_files", "rule_equivalence_mapping_files"),
        "source": ("independence_mapping_files",),
    }.items():
        for key in keys:
            value[section].pop(key)
    return value


def raw_inventory(root):
    """Inspect filenames only: never open truth, ordinary logs, or processed data."""
    root = Path(root).resolve()
    paths = set((root / "data/input/alerts").rglob("*"))
    for directory in (root / "data").glob("*/**/raw"):
        paths.update(directory.rglob("*"))
    return [{"path": p.relative_to(root).as_posix(), "bytes": p.stat().st_size,
             "status": "requires_explicit_source_metadata"} for p in sorted(paths)
            if p.is_file() and p.suffix.lower() in {".json", ".jsonl", ".ndjson"}]


def assert_frozen(root, expected, *, exclude_private_credentials=False):
    root = Path(root)
    changed = [p for p, digest in expected.items()
               if not (root / p).is_file() or file_digest(root / p) != digest]
    # Additions to production are changes too, including a dataset scoring hack.
    watched = {p.relative_to(root).as_posix() for base, pattern in
               (("backend/app", "*.py"), ("configs", "*.yaml"), ("docs", "*.md"))
               for p in (root / base).rglob(pattern)}
    # Explicit Task 09.1 authorization: this exact gitignored credential input
    # is deployment-private, not an algorithm or mapping configuration. Default
    # behavior remains strict for all callers and synthetic isolation tests.
    if exclude_private_credentials:
        watched.discard('configs/llm.local.yaml')
    changed += sorted(watched - expected.keys())
    if changed:
        raise ValueError("task_06_6_freeze_failed:" + ",".join(sorted(set(changed))))
    return {"core_algorithm_changed": False, "verified_file_count": len(expected), "changed_files": []}


def load_dataset(root, path, baseline):
    """No label path is accepted in a production source declaration."""
    root = Path(root).resolve()
    value = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if type(value) is not dict or set(value) != {
        "version", "dataset", "origin", "independence_evidence", "source_config", "sources"
    } or value["version"] != "cross-dataset-v1":
        raise ValueError("invalid_cross_dataset_metadata")
    for key in ("dataset", "origin", "independence_evidence", "source_config"):
        if type(value[key]) is not str or not value[key].strip():
            raise ValueError("missing_dataset_metadata:" + key)
    if value["dataset"] == "russellmitchell":
        raise ValueError("baseline_is_not_cross_dataset")
    config_path = (root / value["source_config"]).resolve()
    if not config_path.is_relative_to(root / "configs"):
        raise ValueError("source_config_must_be_in_configs")
    overlay = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    allowed = {"normalization": {"source_timezones", "host_aliases", "category_mapping_files", "severity_mapping_files"},
               "duplicate": {"payload_mapping_files", "rule_equivalence_mapping_files"},
               "source": {"independence_mapping_files"}}
    if type(overlay) is not dict or any(k not in allowed or type(v) is not dict or set(v) - allowed[k]
                                            for k, v in overlay.items()):
        raise ValueError("source_override_contains_core_parameters")
    config = load_config(root / "configs/algorithm-v0.yaml", deployment_override=root / "configs/sources.yaml",
                         experiment_override=config_path)
    if core_parameters(config) != core_parameters(baseline):
        raise ValueError("core_algorithm_config_changed")
    if type(value["sources"]) is not list or not value["sources"]:
        raise ValueError("missing_dataset_sources")
    inputs, hashes, namespaces = [], {}, set()
    baseline_raw = {file_digest(p) for p in (root / "data/ait_ads/russellmitchell/raw").glob("*.json")}
    for source in value["sources"]:
        if type(source) is not dict or set(source) != {"adapter", "path", "format_reference", "settings"}:
            raise ValueError("invalid_source_declaration")
        if source["adapter"] not in ADAPTERS:
            raise ValueError("adapter_incomplete:unsupported_source")
        if type(source["format_reference"]) is not str or not source["format_reference"].strip():
            raise ValueError("missing_format_reference")
        settings = AdapterSettings(**source["settings"])
        if settings.source_namespace in namespaces or settings.source_namespace in baseline.algorithm.normalization.source_timezones:
            raise ValueError("source_namespace_not_independent")
        namespaces.add(settings.source_namespace)
        if settings.source_namespace not in config.algorithm.normalization.source_timezones:
            raise ValueError("missing_source_timezone")
        p = (root / source["path"]).resolve()
        parts = {s.lower() for s in p.parts}
        if not p.is_relative_to(root / "data") or p.suffix.lower() not in {".json", ".jsonl", ".ndjson"} or not (
            p.is_relative_to(root / "data/input/alerts") or "raw" in parts
        ) or parts & {"evaluation", "processed", "russellmitchell"}:
            raise ValueError("input_path_not_independent_security_alert")
        if not p.is_file():
            raise ValueError("missing_dataset_file")
        digest = file_digest(p)
        if digest in baseline_raw:
            raise ValueError("copied_baseline_is_not_cross_dataset")
        hashes[source["path"]] = digest
        inputs.append((ADAPTERS[source["adapter"]](config, settings), p))
    return value, inputs, {"input_files": hashes, "input_fingerprint": content_digest(sorted(hashes.values())),
                           "source_config_hash": file_digest(config_path),
                           "source_settings_hash": content_digest([a.settings.snapshot() for a, _ in inputs]),
                           "algorithm_config_hash": config.config_hash,
                           "core_algorithm_parameters_hash": content_digest(core_parameters(config)),
                           "mapping_digest": config.mapping_digest}


def compatibility(root):
    """Capabilities of existing parsing implementations; no real migration claim."""
    return {"status": "assessed_existing_adapters_only", "canonical_schema_version": "1.0",
            "adapters": {
                "wazuh": {"profile": "wazuh_json_v1", "product": "Wazuh; explicitly identified Suricata envelopes",
                          "required_fields": ["rule", "@timestamp or timestamp"],
                          "source_sha256": file_digest(Path(root) / "backend/app/adapters/wazuh.py")},
                "aminer": {"profile": "ait_ads_v1_aminer_json", "dataset_version": 1, "epoch_unit": "seconds",
                           "required_fields": ["AnalysisComponent", "LogData.DetectionTimestamp", "component type/name"],
                           "source_sha256": file_digest(Path(root) / "backend/app/adapters/aminer.py")}},
            "limitations": ["Standalone Suricata EVE and other products need an explicitly verified new parsing adapter.",
                            "AMiner supports only the confirmed AIT-ADS v1 profile; other versions are unverified.",
                            "Missing schema fields remain null/unknown; mappings cannot invent facts or relationships.",
                            "An independent source declaration is evidence to review, not automatic proof of dataset independence."]}
