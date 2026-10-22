"""Run adapters → duplicate candidates/dedupe → entities, then stop.

CLI deployment settings are explicit inputs and join the effective snapshot.
No dataset filenames, attack intervals, ground truth or future algorithms are
used by the pipeline. Output domain records are retained as canonical JSONL;
Task 03 owns DuckDB/Parquet storage integration.
"""

import argparse
from collections import Counter
from dataclasses import asdict, dataclass
import json
from pathlib import Path

from app.adapters import AdapterSettings, AMinerAdapter, WazuhAdapter
from app.config import load_config
from app.dedup import deduplicate
from app.entities.extraction import extract_entities
from app.models import EntityType
from app.models.base import resolve_pointer
from app.utils.stable_id import canonical_json, content_digest, id_for


ALGORITHM_VERSION = "preprocessing-v1"
PIPELINE_ROLE = 'LEGACY_HISTORICAL_REPLAY_NOT_OFFICIAL_ANALYSIS_PIPELINE'


@dataclass
class PreprocessingResult:
    analysis_id: str
    alerts: list
    groups: list
    entities: list
    summary: dict
    manifest: dict
    diagnostics: list


def preprocess(inputs, *, output_root=None):
    """inputs is a sequence of (adapter, explicit security alert path) pairs."""
    if not inputs:
        raise ValueError("empty_inputs")
    configs = {adapter.config.config_hash for adapter, _ in inputs}
    if len(configs) != 1:
        raise ValueError("different_effective_algorithm_configs")
    config = inputs[0][0].config
    settings = {}
    for adapter, _ in inputs:
        namespace = adapter.settings.source_namespace
        if namespace in settings and settings[namespace] != adapter.settings:
            raise ValueError("conflicting_source_settings")
        settings[namespace] = adapter.settings
    snapshot = {"algorithm": config.snapshot, "sources": {k: v.snapshot() for k, v in sorted(settings.items())}}
    config_hash = content_digest(snapshot)
    batches = [(adapter, adapter.read_file(path)) for adapter, path in inputs]
    by_id = {}
    for _, batch in batches:
        for alert in batch.alerts:
            if alert.alert_id in by_id and by_id[alert.alert_id].canonical_json() != alert.canonical_json():
                raise ValueError("same_alert_id_conflicting_content")
            by_id[alert.alert_id] = alert
    alerts = [by_id[k] for k in sorted(by_id)]
    if not alerts:
        raise ValueError("no_accepted_alerts")
    analysis_id = id_for("AnalysisRecord", {"input_alert_ids": list(by_id), "config_hash": config_hash,
                                           "algorithm_version": ALGORITHM_VERSION, "schema_version": "1.0"})
    dedupe = deduplicate(alerts, config, settings)
    extracted = extract_entities(alerts, settings)
    alerts = extracted.alerts
    rejection_reasons = Counter()
    diagnostics = list(dedupe.diagnostics)
    for _, batch in batches:
        rejection_reasons.update(batch.rejection_reasons)
        diagnostics.extend({"stage": "adapter", "decision": "reject", **asdict(record)} for record in batch.rejected)
    total_input = sum(batch.input_count for _, batch in batches)
    accepted = sum(batch.accepted_count for _, batch in batches)
    grouped_count = sum(len(group.alert_ids) for group in dedupe.groups)
    counts_by_source = Counter()
    for adapter, batch in batches:
        counts_by_source[adapter.settings.generator.lower()] += batch.input_count
    summary = {
        "total_input_alerts": total_input,
        "wazuh_input_count": counts_by_source["wazuh"], "aminer_input_count": counts_by_source["aminer"],
        "accepted_alert_count": accepted, "rejected_alert_count": total_input - accepted,
        "rejection_reasons": dict(sorted(rejection_reasons.items())),
        "duplicate_import_count": accepted - len(alerts), "canonical_alert_count": len(alerts),
        "severity_distribution": dict(sorted(Counter(a.severity.value for a in alerts).items())),
        "category_distribution": dict(sorted(Counter(a.category.value for a in alerts).items())),
        "source_type_distribution": dict(sorted(Counter(a.source_type.value for a in alerts).items())),
        "dedupe_group_count": len(dedupe.groups), "alerts_in_dedupe_groups": grouped_count,
        "representative_count": len(alerts) - grouped_count + len(dedupe.groups),
        "entity_count": len(extracted.entities),
        "entity_count_by_type": {kind.value: sum(e.type == kind for e in extracted.entities) for kind in EntityType},
        "dedupe_candidate_count": dedupe.candidate_count, "dedupe_verified_pair_count": dedupe.verified_pair_count,
        "dedupe_is_complete": dedupe.is_complete,
    }
    reference = "outputs/analyses/" + analysis_id
    incomplete = total_input != accepted or not dedupe.is_complete
    manifest = {"analysis_id": analysis_id, "config_hash": config_hash, "config_digest": config_hash,
                "config_snapshot": snapshot, "mapping_digest": config.mapping_digest,
                "dataset_digest": content_digest([[a.alert_id, a.raw_fingerprint] for a in alerts]),
                "algorithm_version": ALGORITHM_VERSION, "schema_version": "1.0",
                "status": "incomplete" if incomplete else "completed", "is_complete": not incomplete,
                "incomplete_reason": dedupe.incomplete_reason or ("rejected_input_records" if total_input != accepted else None),
                "candidate_truncated": False, "summary": summary,
                "diagnostics_ref": reference + "/diagnostics.jsonl",
                "frequency_snapshot_ref": reference + "/frequency_snapshot.json",
                "domain_ref": "data/processed/" + analysis_id}
    # Validate raw-pointer closure before publishing, independent of model shape.
    for alert in alerts:
        for occurrence in alert.entity_occurrences:
            resolve_pointer(alert.raw_alert, occurrence.raw_pointer)
    diagnostics.sort(key=canonical_json)
    result = PreprocessingResult(analysis_id, alerts, dedupe.groups, extracted.entities, summary, manifest, diagnostics)
    if output_root is not None:
        write_result(result, output_root)
    return result


def write_result(result, output_root):
    root = Path(output_root).resolve()
    domain = root / "data/processed" / result.analysis_id
    diagnostics = root / "outputs/analyses" / result.analysis_id
    domain.mkdir(parents=True, exist_ok=True)
    diagnostics.mkdir(parents=True, exist_ok=True)
    def jsonl(path, values):
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            for value in values:
                handle.write(value.canonical_json() if hasattr(value, "canonical_json") else canonical_json(value))
                handle.write("\n")
    jsonl(domain / "alerts.jsonl", result.alerts)
    jsonl(domain / "dedupe_groups.jsonl", result.groups)
    jsonl(domain / "entities.jsonl", result.entities)
    (domain / "preprocessing_summary.json").write_text(canonical_json(result.summary) + "\n", encoding="utf-8")
    jsonl(diagnostics / "diagnostics.jsonl", result.diagnostics)
    # Entity rarity/frequency scoring belongs to Task 03; no invented N/df here.
    (diagnostics / "frequency_snapshot.json").write_text(canonical_json({"status": "not_computed_in_task02"}) + "\n", encoding="utf-8")
    (diagnostics / "manifest.json").write_text(canonical_json(result.manifest) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Task 02 deterministic alert preprocessing")
    parser.add_argument("--algorithm", required=True)
    parser.add_argument("--sources", required=True)
    parser.add_argument("--wazuh", required=True)
    parser.add_argument("--aminer", required=True)
    parser.add_argument("--wazuh-namespace", required=True)
    parser.add_argument("--aminer-namespace", required=True)
    parser.add_argument("--aminer-profile", required=True)
    parser.add_argument("--epoch-unit", required=True, choices=["seconds"])
    parser.add_argument("--dataset-version", required=True, type=int)
    parser.add_argument("--network-namespace")
    parser.add_argument("--output-root", required=True)
    args = parser.parse_args()
    config = load_config(args.algorithm, deployment_override=args.sources)
    wazuh = WazuhAdapter(config, AdapterSettings(args.wazuh_namespace, "wazuh_json_v1", "Wazuh",
                          dataset_version=args.dataset_version, network_namespace=args.network_namespace))
    aminer = AMinerAdapter(config, AdapterSettings(args.aminer_namespace, args.aminer_profile, "AMiner",
                           dataset_version=args.dataset_version, epoch_unit=args.epoch_unit, network_namespace=args.network_namespace))
    result = preprocess([(wazuh, args.wazuh), (aminer, args.aminer)], output_root=args.output_root)
    print(json.dumps({"analysis_id": result.analysis_id, "summary": result.summary}, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
