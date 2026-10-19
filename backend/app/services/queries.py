"""Read fixed, analysis-scoped Parquet snapshots. No algorithm imports/calls."""

import json
from pathlib import Path
import re
import threading
from contextlib import contextmanager

import duckdb

from app.models import EvaluationSummaryExport
from app.models.base import resolve_pointer
from app.services.storage import MODELS, SnapshotStore, checked_id, file_digest
from app.utils.stable_id import id_for


class QueryError(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code


class QueryService:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.integrity_cache = {}
        self.lock = threading.Lock()

    @contextmanager
    def connection(self):
        with duckdb.connect(":memory:") as db:
            try:
                yield db
            except duckdb.Error as exc:
                raise QueryError(409, "snapshot_integrity_error") from exc

    def store(self, analysis_id):
        try:
            store = SnapshotStore(self.root, checked_id(analysis_id))
        except ValueError:
            raise QueryError(404, "analysis_not_found")
        if not (store.domain / "run.json").is_file():
            raise QueryError(404, "analysis_not_found")
        return store

    def analysis(self, analysis_id):
        store = self.store(analysis_id)
        try:
            # The manifest is the publication marker, not the worker's earlier
            # checkpoint. It prevents readers seeing half-published tables.
            manifest = json.loads((store.details / "manifest.json").read_text(encoding="utf-8"))
            if manifest["analysis_id"] != analysis_id:
                raise ValueError("analysis_scope_mismatch")
            record = None
            if "execution" in manifest:
                record, _, verified = store.read_metadata(verify_files=False)
                result = dict(verified["summary"])
                self.verify(store.domain / "run.json", manifest["files"]["run.json"])
                if json.loads((store.domain / "run.json").read_text(encoding="utf-8")) != result:
                    raise ValueError("run_manifest_mismatch")
            else:
                result = {k: v for k, v in manifest.items() if k not in {"schema_version", "domain_ref"}}
            if result["analysis_id"] != analysis_id:
                raise ValueError("analysis_scope_mismatch")
            return {**{k: v for k, v in result.items() if k != "owner_pid"}, "record": record}
        except (ValueError, KeyError, OSError) as exc:
            raise QueryError(409, "snapshot_integrity_error") from exc

    def ready(self, analysis_id):
        result = self.analysis(analysis_id)
        if result["record"] is None or result["status"] not in {"completed", "incomplete"}:
            raise QueryError(409, "analysis_not_ready")
        return self.store(analysis_id)

    def verify(self, path, expected):
        try:
            stat = path.stat()
            key = (str(path), stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns, expected)
            with self.lock:
                if key not in self.integrity_cache:
                    if file_digest(path) != expected:
                        raise QueryError(409, "snapshot_integrity_error")
                    self.integrity_cache[key] = True
        except OSError as exc:
            raise QueryError(409, "snapshot_integrity_error") from exc

    def table(self, store, kind):
        if kind not in MODELS:
            raise QueryError(409, "unknown_snapshot_table")
        manifest = json.loads((store.details / "manifest.json").read_text(encoding="utf-8"))
        filename = kind + ".parquet"
        path = store.domain / filename
        try:
            self.verify(path, manifest["files"][filename])
        except KeyError as exc:
            raise QueryError(409, "snapshot_integrity_error") from exc
        return str(path)

    def parsed(self, kind, payload):
        model, field = MODELS[kind]
        try:
            value = model.model_validate_json(payload)
        except ValueError as exc:
            raise QueryError(409, "snapshot_integrity_error") from exc
        if getattr(value, field) != id_for(model.__name__, value):
            raise QueryError(409, "snapshot_identity_error")
        return value

    def get(self, analysis_id, kind, object_id):
        store = self.ready(analysis_id)
        path = self.table(store, kind)
        with self.connection() as db:
            row = db.execute("SELECT payload FROM read_parquet(?) WHERE object_id = ?", [path, object_id]).fetchone()
        if row is None:
            raise QueryError(404, kind.rstrip("s") + "_not_found")
        try:
            return self.parsed(kind, row[0])
        except ValueError as exc:
            raise QueryError(409, "snapshot_integrity_error") from exc

    def by_ids(self, analysis_id, kind, identities):
        if not identities:
            return []
        store = self.ready(analysis_id)
        with self.connection() as db:
            rows = db.execute("SELECT payload FROM read_parquet(?) WHERE object_id IN (SELECT unnest(?)) ORDER BY object_id",
                              [self.table(store, kind), sorted(set(identities))]).fetchall()
        values = [self.parsed(kind, r[0]) for r in rows]
        if len(values) != len(set(identities)):
            raise QueryError(409, "snapshot_reference_missing")
        return values

    def list(self, analysis_id, kind, *, page, page_size, filters):
        store = self.ready(analysis_id)
        path = self.table(store, kind)
        clauses, values = [], [path]
        for key, value in filters.items():
            if value is None:
                continue
            if key in {"start_time", "end_time"}:
                time_field = "timestamp" if kind == "alerts" else "end_time"
                op = ">=" if key == "start_time" else "<"
                clauses.append(f"CAST(json_extract_string(payload, '$.{time_field}') AS TIMESTAMPTZ) {op} CAST(? AS TIMESTAMPTZ)")
            else:
                if key not in ({"source_type", "severity", "category"} if kind == "alerts" else {"severity", "status"}):
                    raise QueryError(400, "unknown_filter")
                clauses.append(f"json_extract_string(payload, '$.{key}') = ?")
            values.append(value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self.connection() as db:
            total = db.execute("SELECT count(*) FROM read_parquet(?)" + where, values).fetchone()[0]
            rows = db.execute("SELECT payload FROM read_parquet(?)" + where + " ORDER BY event_time DESC, object_id ASC LIMIT ? OFFSET ?",
                              [*values, page_size, (page-1)*page_size]).fetchall()
        return {"items": [self.parsed(kind, r[0]) for r in rows], "page": page, "page_size": page_size, "total": total}

    def chain(self, analysis_id, incident_id):
        incident = self.get(analysis_id, "incidents", incident_id)
        store = self.ready(analysis_id)
        with self.connection() as db:
            rows = db.execute("SELECT payload FROM read_parquet(?) WHERE json_extract_string(payload, '$.incident_id') = ?",
                              [self.table(store, "attack_chains"), incident_id]).fetchall()
        if len(rows) != 1:
            raise QueryError(409, "snapshot_chain_missing")
        chain = self.parsed("attack_chains", rows[0][0])
        if set(aid for n in chain.nodes for aid in n.alert_ids) != set(incident.alert_ids):
            raise QueryError(409, "snapshot_chain_membership_mismatch")
        nodes = self.by_ids(analysis_id, "chain_nodes", [n.node_id for n in chain.nodes])
        edges = self.by_ids(analysis_id, "chain_edges", [e.edge_id for e in chain.edges])
        if nodes != chain.nodes or edges != chain.edges:
            raise QueryError(409, "snapshot_embedded_objects_mismatch")
        alerts = self.by_ids(analysis_id, "alerts", incident.alert_ids)
        self.by_ids(analysis_id, "entities", incident.entity_ids)
        for alert in alerts:
            try:
                for provenance in alert.field_provenance.values():
                    resolve_pointer(alert.raw_alert, provenance.raw_pointer)
                for occurrence in alert.entity_occurrences:
                    resolve_pointer(alert.raw_alert, occurrence.raw_pointer)
            except ValueError as exc:
                raise QueryError(409, "snapshot_evidence_pointer_missing") from exc
        self.by_ids(analysis_id, "correlation_edges", incident.correlation_edge_ids)
        return chain

    def edge(self, analysis_id, edge_id):
        edge = self.get(analysis_id, "chain_edges", edge_id)
        nodes = self.by_ids(analysis_id, "chain_nodes", [edge.source_node_id, edge.target_node_id])
        incident = self.get(analysis_id, "incidents", edge.incident_id)
        if any(n.incident_id != incident.incident_id for n in nodes):
            raise QueryError(409, "snapshot_edge_scope_mismatch")
        correlations = self.by_ids(analysis_id, "correlation_edges", edge.correlation_edge_ids)
        if not set(edge.correlation_edge_ids) <= set(incident.correlation_edge_ids):
            raise QueryError(409, "snapshot_edge_scope_mismatch")
        selected = next((c for c in correlations if c.edge_id == edge.score_breakdown.selected_correlation_edge_id), None)
        breakdown = edge.score_breakdown.model_dump()
        breakdown["selected_correlation_edge_id"] = None
        if selected is None or selected.score_breakdown.model_dump() != breakdown:
            raise QueryError(409, "snapshot_selected_breakdown_mismatch")
        identities = set(edge.alert_ids) | {a for n in nodes for a in n.alert_ids}
        identities |= {a for c in correlations for a in (c.support_pair.alert_id_src, c.support_pair.alert_id_dst)}
        if not identities <= set(incident.alert_ids):
            raise QueryError(409, "snapshot_edge_scope_mismatch")
        alerts = {a.alert_id: a for a in self.by_ids(analysis_id, "alerts", identities)}
        entity_ids = set(edge.entity_ids) | {e for c in correlations for e in c.entity_ids}
        self.by_ids(analysis_id, "entities", entity_ids)
        for reason in [*edge.reasons, *(r for c in correlations for r in c.reasons)]:
            for pointer in reason.params.get("raw_pointers", []):
                try:
                    resolve_pointer(alerts[pointer["alert_id"]].raw_alert, pointer["pointer"])
                except (ValueError, KeyError) as exc:
                    raise QueryError(409, "snapshot_evidence_pointer_missing") from exc
        return edge, correlations

    def timeline(self, analysis_id, incident_id, *, page, page_size, start_time=None, end_time=None):
        incident = self.get(analysis_id, "incidents", incident_id)
        chain = self.chain(analysis_id, incident_id)
        alerts = self.by_ids(analysis_id, "alerts", incident.alert_ids)
        by_id = {a.alert_id: a for a in alerts}
        items = [{"id": a.alert_id, "kind": "alert", "alert_ids": [a.alert_id], "node_id": None,
                  "event_time": a.timestamp, "end_time": a.timestamp, "source_type": a.source_type,
                  "sensor": a.sensor} for a in alerts]
        for node in chain.nodes:
            # One node can occupy several source/sensor lanes. Same node ID is
            # a reference, never a fabricated causal step. Lane tie is explicit.
            lanes = sorted({(by_id[aid].source_type.value, by_id[aid].sensor) for aid in node.alert_ids}, key=lambda v: (v[0], v[1] or ""))
            for source, sensor in lanes:
                items.append({"id": node.node_id, "kind": "node", "alert_ids": node.alert_ids, "node_id": node.node_id,
                              "event_time": node.start_time, "end_time": node.end_time, "source_type": source, "sensor": sensor})
        items = sorted((i for i in items if (start_time is None or i["event_time"] >= start_time)
                        and (end_time is None or i["event_time"] < end_time)),
                       key=lambda i: (i["event_time"], i["id"], str(i["source_type"]), i["sensor"] or ""))
        return {"items": items[(page-1)*page_size:page*page_size], "page": page, "page_size": page_size, "total": len(items)}

    def evaluation(self, analysis_id, run_id):
        self.analysis(analysis_id)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", run_id):
            raise QueryError(404, "evaluation_export_not_found")
        directory = self.root / "data/processed/evaluation_exports"
        path = directory / (run_id + ".json")
        if path.resolve() != path.absolute() or not path.is_file():
            raise QueryError(404, "evaluation_export_not_found")
        try:
            export = EvaluationSummaryExport.model_validate_json(path.read_text(encoding="utf-8"))
            if export.run_id != run_id:
                raise ValueError("export_identity_mismatch")
            return export
        except ValueError as exc:
            raise QueryError(409, "invalid_evaluation_export") from exc
