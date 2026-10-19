"""Analysis-partitioned DuckDB/Parquet and verified snapshot files."""

from contextlib import contextmanager
import json
from pathlib import Path
import re

import duckdb

from app.adapters.base import AdapterSettings
from app.config import AlgorithmConfig, EffectiveConfig, MAPPING_REFERENCES, MappingFile, _digest, _snapshot
from app.models import (AnalysisRecord, AttackChain, CanonicalAlert, ChainEdge, ChainNode,
                        CorrelationEdge, DedupeGroup, Entity, Incident)
from app.utils.stable_id import canonical_json, content_digest, id_for


MODELS = {"alerts": (CanonicalAlert, "alert_id"), "entities": (Entity, "entity_id"),
          "dedupe_groups": (DedupeGroup, "group_id"), "correlation_edges": (CorrelationEdge, "edge_id"),
          "incidents": (Incident, "incident_id"), "chain_nodes": (ChainNode, "node_id"),
          "chain_edges": (ChainEdge, "edge_id"), "attack_chains": (AttackChain, "chain_id")}


class RunAnalysisRecord(AnalysisRecord):
    """Task 05's explicitly requested independent execution identity.

    Fields, enums and every snapshot validator remain the frozen v1 contract.
    Only Analysis identity differs from legacy deterministic stage snapshots.
    SnapshotStore verifies the run token and records the deterministic identity
    separately in manifest.execution; algorithm object IDs are unchanged.
    """
    def identity_matches(self):
        return self


def run_identity(token):
    if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token):
        raise ValueError("invalid_run_token")
    return "ana_" + content_digest({"kind": "analysis_run", "token": token})


def parse_analysis_record(data, execution=None):
    if execution is None:
        return AnalysisRecord.model_validate(data)
    record = RunAnalysisRecord.model_validate(data)
    if run_identity(execution["token"]) != record.analysis_id:
        raise ValueError("analysis_run_identity_mismatch")
    if execution["snapshot_identity"] != id_for("AnalysisRecord", record):
        raise ValueError("analysis_snapshot_identity_mismatch")
    return record


def logical_record(record):
    """Restore the original stage identity for the unchanged grounding verifier."""
    data = record.model_dump()
    identity = id_for("AnalysisRecord", record)
    data.update(analysis_id=identity, diagnostics_ref=f"outputs/analyses/{identity}/diagnostics.jsonl",
                frequency_snapshot_ref=f"outputs/analyses/{identity}/frequency_snapshot.json")
    return AnalysisRecord.model_validate(data)


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(canonical_json(value) + "\n", encoding="utf-8")
    temporary.replace(path)


def checked_id(value):
    if type(value) is not str or not re.fullmatch(r"ana_[0-9a-f]{64}", value):
        raise ValueError("invalid_analysis_id")
    return value


def restore_config(snapshot):
    """Revalidate the frozen loader's expanded snapshot without path references."""
    algorithm = json.loads(canonical_json(snapshot))
    mappings = []
    for section, field, kind in MAPPING_REFERENCES:
        files = algorithm[section][field]
        mappings.extend(MappingFile.model_validate(item, context=None).model_dump() for item in files)
        if any(item["mapping_type"] != kind for item in files):
            raise ValueError("snapshot_mapping_type_mismatch")
        algorithm[section][field] = []
    validated = AlgorithmConfig.model_validate(algorithm)
    # Require canonical loader semantics, including set/matrix ordering.
    normalized = _snapshot(validated)
    for section, field, _ in MAPPING_REFERENCES:
        files = snapshot[section][field]
        normalized[section][field] = sorted([MappingFile.model_validate(item).model_dump() for item in files], key=_digest)
    digest = content_digest(normalized)
    return EffectiveConfig(canonical_json(normalized), digest, digest, _digest(sorted(mappings, key=_digest)),
                           canonical_json(validated.model_dump()))


class SnapshotStore:
    def __init__(self, root, analysis_id):
        self.root = Path(root).resolve()
        self.analysis_id = checked_id(analysis_id)
        self.domain = self.root / "data" / "processed" / analysis_id
        self.details = self.root / "outputs" / "analyses" / analysis_id

    def create(self):
        self.domain.mkdir(parents=True, exist_ok=True)
        self.details.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def diagnostics_writer(self, *, bounded=False):
        self.create()
        path = self.details / "diagnostics.jsonl"
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            if bounded:
                from .bounded_diagnostics import BoundedDiagnostics
                sink = BoundedDiagnostics(self.details, handle)
                try:
                    yield sink
                finally:
                    sink.close()
                return
            # Diagnostics preserve unrounded floats and have no domain identity.
            # Stable sorted-key JSON avoids repeatedly applying Stable-ID decimal
            # normalization to millions of already normalized fact references.
            yield lambda record: handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True,
                                                        separators=(",", ":"), allow_nan=False) + "\n")

    def write_records(self, kind, records):
        if kind not in MODELS:
            raise ValueError("unknown_domain_table")
        self.create()
        model, identity_field = MODELS[kind]
        db = duckdb.connect(str(self.domain / "domain.duckdb"))
        try:
            from app.services.capacity import execution_state
            bounded = execution_state() is not None
            if bounded:
                db.execute("SET memory_limit='512MB'")
                db.execute('SET threads=1')
            db.execute("BEGIN TRANSACTION")
            db.execute(f"CREATE TABLE IF NOT EXISTS {kind} (object_id VARCHAR PRIMARY KEY, payload VARCHAR NOT NULL, event_time TIMESTAMPTZ)")
            db.execute(f"DELETE FROM {kind}")
            count, max_line_bytes = 0, 1
            with (self.domain / (kind + ".jsonl")).open("w", encoding="utf-8", newline="\n") as handle:
                for record in records:
                    parsed = model.model_validate(record.model_dump() if hasattr(record, "model_dump") else record)
                    identity = getattr(parsed, identity_field)
                    if id_for(model.__name__, parsed) != identity:
                        raise ValueError("storage_object_identity_mismatch")
                    payload = parsed.canonical_json()
                    handle.write(payload + "\n")
                    count += 1
                    max_line_bytes = max(max_line_bytes, len(payload.encode("utf-8")) + 1)
            if count:
                # Scan canonical JSONL as one text column, preserving payload
                # bytes. JSON escapes control characters/newlines, so a literal
                # unit separator cannot occur. Avoid Python array conversion:
                # DuckDB otherwise repeatedly probes optional pandas for each
                # nested parameter when pandas is not installed.
                time_field = {"alerts": "timestamp", "incidents": "end_time", "chain_nodes": "start_time"}.get(kind)
                timestamp = f"CAST(json_extract_string(payload, '$.{time_field}') AS TIMESTAMPTZ)" if time_field else "NULL"
                db.execute(f"INSERT INTO {kind} SELECT json_extract_string(payload, '$.{identity_field}'), payload, {timestamp} "
                           "FROM read_csv(?, auto_detect=false, header=false, delim='\\x1f', quote='', escape='', "
                           "columns={'payload':'VARCHAR'}, max_line_size=?)",
                           [str(self.domain / (kind + ".jsonl")), max_line_bytes + 16])
            parquet_path = str(self.domain / (kind + ".parquet")).replace("'", "''")
            # The default 122880-row Parquet group can retain the complete raw
            # payload population while allocating compression buffers. Bound
            # that writer buffer without changing rows or their stable order.
            parquet_options = "FORMAT PARQUET, ROW_GROUP_SIZE 2048" if bounded else "FORMAT PARQUET"
            db.execute(f"COPY (SELECT * FROM {kind} ORDER BY object_id) TO '{parquet_path}' ({parquet_options})")
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
        finally:
            db.close()

    def read_records(self, kind, *, parquet=False, context=None):
        if kind not in MODELS:
            raise ValueError("unknown_domain_table")
        model, _ = MODELS[kind]
        db = duckdb.connect(":memory:" if parquet else str(self.domain / "domain.duckdb"), read_only=not parquet)
        try:
            from app.services.capacity import execution_state
            state = execution_state()
            if state is not None:
                # Legacy snapshots have 122880-row groups (~542 MiB decoded
                # payload); reserve enough to decode one, never sort all raw.
                db.execute("SET memory_limit='768MB'")
                db.execute('SET threads=1')
                db.execute('SET temp_directory=?', [str(state.directory/'duckdb_read')])
                # Sorting wide raw payloads can exhaust even a spilling sort.
                # Scan sequential vectors, sort exact narrow keys on disk, then
                # recover one validated payload at a time in the original order.
                import zlib
                order_db = state.database()
                order_db.execute('CREATE TABLE read_rows (ordinal INTEGER PRIMARY KEY, object_id TEXT, payload BLOB)')
                cursor = db.execute('SELECT object_id,payload FROM read_parquet(?)',
                    [str(self.domain/(kind+'.parquet'))]) if parquet else db.execute(f'SELECT object_id,payload FROM {kind}')
                ordinal = 0
                while rows := cursor.fetchmany(1024):
                    if hasattr(state, 'resource_check'):
                        state.resource_check()
                    order_db.executemany('INSERT INTO read_rows VALUES (?,?,?)',
                        ((ordinal+i, identity, zlib.compress(payload.encode('utf8'), 1))
                         for i, (identity, payload) in enumerate(rows)))
                    ordinal += len(rows)
                order_db.execute('CREATE INDEX read_order ON read_rows(object_id,ordinal)')
                order_db.commit()
                for (payload,) in order_db.execute('SELECT payload FROM read_rows ORDER BY object_id,ordinal'):
                    yield model.model_validate_json(zlib.decompress(payload), context=context)
                order_db.execute('DROP TABLE read_rows')
                order_db.commit()
                return
            if parquet:
                cursor = db.execute("SELECT payload FROM read_parquet(?) ORDER BY object_id", [str(self.domain / (kind + ".parquet"))])
            else:
                cursor = db.execute(f"SELECT payload FROM {kind} ORDER BY object_id")
            while rows := cursor.fetchmany(1024):
                for (payload,) in rows:
                    yield model.model_validate_json(payload, context=context)
        finally:
            db.close()

    def write_metadata(self, record, frequency, summary, *, execution=None):
        record = parse_analysis_record(record.model_dump(), execution)
        if record.analysis_id != self.analysis_id:
            raise ValueError("analysis_identity_mismatch")
        self.create()
        atomic_json(self.domain / "analysis.json", record.model_dump(mode="json"))
        frequency_payload = canonical_json(frequency)
        (self.details / "frequency_snapshot.json").write_text(frequency_payload + "\n", encoding="utf-8")
        manifest = {**record.model_dump(mode="json"), "domain_ref": f"data/processed/{self.analysis_id}",
                    "summary": summary, "frequency_digest": content_digest(frequency),
                    "files": {p.name: file_digest(p) for p in sorted(self.domain.iterdir()) if p.suffix in {".json", ".jsonl", ".parquet"}},
                    "diagnostics_digest": file_digest(self.details / "diagnostics.jsonl")}
        if summary and summary.get("candidate_contract_version"):
            manifest["candidate_contract_version"] = summary["candidate_contract_version"]
        if execution is not None:
            manifest["execution"] = execution
        if (self.details/'bounded_diagnostics.json').exists():
            manifest['diagnostic_storage_version'] = 'bounded-diagnostics-v1'
            manifest['diagnostic_files'] = {p.relative_to(self.details).as_posix():file_digest(p)
                for p in sorted(self.details.rglob('*')) if p.is_file() and
                (p.suffix == '.parquet' or p.name == 'bounded_diagnostics.json')}
        atomic_json(self.details / "manifest.json", manifest)

    def read_metadata(self, *, verify_files=True):
        manifest = json.loads((self.details / "manifest.json").read_text(encoding="utf-8"))
        record = parse_analysis_record(json.loads((self.domain / "analysis.json").read_text(encoding="utf-8")), manifest.get("execution"))
        if record.analysis_id != self.analysis_id:
            raise ValueError("analysis_identity_mismatch")
        if any(manifest.get(k) != v for k, v in record.model_dump(mode="json").items()):
            raise ValueError("manifest_record_mismatch")
        if manifest["domain_ref"] != f"data/processed/{self.analysis_id}":
            raise ValueError("manifest_domain_reference_mismatch")
        frequency = json.loads((self.details / "frequency_snapshot.json").read_text(encoding="utf-8"))
        if content_digest(frequency) != manifest["frequency_digest"]:
            raise ValueError("frequency_digest_mismatch")
        if verify_files and file_digest(self.details / "diagnostics.jsonl") != manifest["diagnostics_digest"]:
            raise ValueError("diagnostics_digest_mismatch")
        for relative, expected in manifest.get('diagnostic_files', {}).items():
            path = (self.details/relative).resolve()
            if not path.is_relative_to(self.details) or path.suffix not in ('.parquet','.json'):
                raise ValueError('unapproved_diagnostic_file')
            if verify_files and file_digest(path) != expected:
                raise ValueError('bounded_diagnostic_digest_mismatch')
        for filename, digest in manifest["files"].items():
            if filename not in {k + ext for k in MODELS for ext in (".jsonl", ".parquet")} | {"analysis.json", "run.json"}:
                raise ValueError("unapproved_manifest_file")
            if verify_files and file_digest(self.domain / filename) != digest:
                raise ValueError("domain_digest_mismatch")
        return record, frequency, manifest

    def validate_reconstruction(self, *, parquet=False):
        """Reload the same analysis partition and validate the full Task 04 closure.

        Existing Task 02/03 tables and serialization keep their exact semantics.
        Nodes/edges are indexed individually and embedded in AttackChain; both
        representations must agree before a reader accepts the chain snapshot.
        """
        from app.chains.grounding import validate_grounding
        from app.correlation.index import AlertIndex
        from app.correlation.scoring import CorrelationScorer
        record, frequency, _ = self.read_metadata()
        config = restore_config(record.config_snapshot["algorithm"])
        settings = {key: AdapterSettings(**value) for key, value in record.config_snapshot["sources"].items()}
        loaded = {kind: list(self.read_records(kind, parquet=parquet)) for kind in MODELS}
        index = AlertIndex(loaded["alerts"], loaded["dedupe_groups"], loaded["entities"])
        scorer = CorrelationScorer(index, config, settings, record.config_hash)
        if frequency != index.frequency_snapshot():
            raise ValueError("reconstruction_frequency_mismatch")
        for kind, field, embedded in (
            ("chain_nodes", "node_id", [n for c in loaded["attack_chains"] for n in c.nodes]),
            ("chain_edges", "edge_id", [e for c in loaded["attack_chains"] for e in c.edges])):
            actual = [v.canonical_json() for v in loaded[kind]]
            expected = [v.canonical_json() for v in sorted(embedded, key=lambda v: getattr(v, field))]
            if actual != expected:
                raise ValueError("reconstruction_embedded_objects_mismatch:" + kind)
        report = validate_grounding(index, loaded["incidents"], loaded["attack_chains"],
                                    loaded["correlation_edges"], scorer, logical_record(record))
        report.require_valid()
        return report


def file_digest(path):
    from hashlib import sha256
    digest = sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def read_preprocessing(root, analysis_id):
    store = SnapshotStore(root, analysis_id)
    manifest = json.loads((store.details / "manifest.json").read_text(encoding="utf-8"))
    if manifest["analysis_id"] != analysis_id or not manifest["is_complete"] or manifest["status"] != "completed":
        raise ValueError("preprocessing_not_complete")
    snapshot = manifest["config_snapshot"]
    if content_digest(snapshot) != manifest["config_hash"] or manifest["config_digest"] != manifest["config_hash"]:
        raise ValueError("preprocessing_config_digest_mismatch")
    config = restore_config(snapshot["algorithm"])
    if config.mapping_digest != manifest["mapping_digest"]:
        raise ValueError("preprocessing_mapping_digest_mismatch")
    settings = {k: AdapterSettings(**v) for k, v in snapshot["sources"].items()}
    records = {}
    for kind in ("alerts", "dedupe_groups", "entities"):
        model, _ = MODELS[kind]
        with (store.domain / (kind + ".jsonl")).open(encoding="utf-8") as handle:
            records[kind] = [model.model_validate_json(line) for line in handle if line.strip()]
    digest = content_digest([[a.alert_id, a.raw_fingerprint] for a in sorted(records["alerts"], key=lambda a: a.alert_id)])
    if digest != manifest["dataset_digest"]:
        raise ValueError("preprocessing_dataset_digest_mismatch")
    if id_for("AnalysisRecord", {"input_alert_ids": [a.alert_id for a in records["alerts"]], "config_hash": manifest["config_hash"],
                                 "algorithm_version": manifest["algorithm_version"], "schema_version": manifest["schema_version"]}) != analysis_id:
        raise ValueError("preprocessing_identity_mismatch")
    return records, config, settings, manifest
