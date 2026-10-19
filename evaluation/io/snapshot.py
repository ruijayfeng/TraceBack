"""Read and bind a completed immutable production snapshot before opening GT."""

from dataclasses import dataclass
import json
from pathlib import Path

from app.adapters.base import AdapterSettings
from app.correlation.index import event_microseconds
from app.services.storage import SnapshotStore, file_digest, restore_config
from app.utils.stable_id import content_digest


@dataclass
class PredictionSnapshot:
    store: SnapshotStore
    record: object
    manifest: dict
    frequency: dict
    config: object
    settings: dict
    alerts: dict
    groups: dict
    owner: dict
    entities: dict
    artifact_hashes: dict

    @property
    def identity(self):
        r = self.record
        return {"analysis_id": r.analysis_id, "algorithm_version": r.algorithm_version,
                "config_hash": r.config_hash, "mapping_digest": r.mapping_digest,
                "dataset_digest": r.dataset_digest, "candidate_contract_version": self.manifest.get("candidate_contract_version"),
                "input_count": self.manifest["summary"].get("counts", {}).get("input_count", len(self.alerts)),
                "canonical_alert_count": len(self.alerts), "representative_count": len(self.groups),
                "prediction_snapshot": str(self.store.domain), "artifact_hashes": self.artifact_hashes}

    def records(self, kind):
        with (self.store.domain / (kind + ".jsonl")).open(encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    yield json.loads(line)

    def assert_unchanged(self):
        for relative, digest in self.artifact_hashes.items():
            if file_digest(self.store.root / relative) != digest:
                raise ValueError("production_snapshot_changed:" + relative)


def load_snapshot(root, analysis_id):
    store = SnapshotStore(root, analysis_id)
    record, frequency, manifest = store.read_metadata()  # verifies all stored digests
    if record.status.value != "completed" or not record.is_complete or record.candidate_truncated:
        raise ValueError("evaluation_requires_completed_snapshot")
    if content_digest(record.config_snapshot) != record.config_hash:
        raise ValueError("snapshot_config_digest_mismatch")
    config = restore_config(record.config_snapshot["algorithm"])
    if config.mapping_digest != record.mapping_digest:
        raise ValueError("snapshot_mapping_digest_mismatch")
    summary = manifest["summary"]
    if summary.get("resource_truncated_count", 0):
        raise ValueError("evaluation_requires_no_resource_truncation")
    # Only compact extracted facts remain in memory; raw_alert is kept in the
    # immutable production artifact and is not copied into evaluation tables.
    alerts = {}
    for a in store.read_records("alerts", parquet=True):
        alerts[a.alert_id] = {"alert_id": a.alert_id, "time_us": event_microseconds(a),
            "timestamp": a.timestamp, "source_type": a.source_type.value, "category": a.category.value,
            "entity_ids": a.entity_ids, "raw_fingerprint": a.raw_fingerprint,
            "relation_count": len(a.relations), "provenance_fields": len(a.field_provenance),
            "entity_roles": {eid: sorted({o.role.value for o in a.entity_occurrences if o.entity_id == eid}) for eid in a.entity_ids},
            "process_instance_entities": [o.entity_id for o in a.entity_occurrences if o.role.value in {"process", "parent_process"}
                and a.host is not None and getattr(a, o.role.value).pid is not None and getattr(a, o.role.value).start_time is not None]}
    if sorted(alerts) != record.input_alert_ids:
        raise ValueError("snapshot_input_ids_mismatch")
    if content_digest([[i, alerts[i]["raw_fingerprint"]] for i in sorted(alerts)]) != record.dataset_digest:
        raise ValueError("snapshot_dataset_digest_mismatch")
    owner = {i: i for i in alerts}
    for g in store.read_records("dedupe_groups", parquet=True):
        for i in g.alert_ids:
            if i not in owner or owner[i] != i:
                raise ValueError("snapshot_dedupe_membership_invalid")
            owner[i] = g.representative_alert_id
    groups = {}
    for aid, rep in sorted(owner.items()):
        groups.setdefault(rep, []).append(aid)
    entities = {e.entity_id: {"type": e.type.value, "scope": e.scope, "value": e.value}
                for e in store.read_records("entities", parquet=True)}
    hashes = {str((store.domain / f).relative_to(store.root)).replace("\\", "/"): d
              for f, d in manifest["files"].items()}
    for filename in ("diagnostics.jsonl", "frequency_snapshot.json", "manifest.json"):
        p = store.details / filename
        hashes[p.relative_to(store.root).as_posix()] = file_digest(p)
    return PredictionSnapshot(store, record, manifest, frequency, config,
        {k: AdapterSettings(**v) for k, v in record.config_snapshot["sources"].items()},
        alerts, groups, owner, entities, hashes)


def protect_output(root, destination, gt_path):
    """Evaluation output cannot overwrite production, sources, or ground truth."""
    root, destination, gt_path = Path(root).resolve(), Path(destination).resolve(), Path(gt_path).resolve()
    allowed = root / "outputs" / "evaluation"
    if not destination.is_relative_to(allowed) or gt_path.is_relative_to(destination):
        raise ValueError("evaluation_output_must_be_in_outputs_evaluation")
    return destination
