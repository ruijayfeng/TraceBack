"""Task 09 acceptance of existing production snapshots and HTTP objects.

No detector, scoring policy, identity scheme or evaluation inputs live here.
The validation receipt caches a successful existing production verifier for
exactly the same manifest, artifact bytes and backend implementation.
"""

import argparse
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))


def expected_snapshot(context):
    settings = [context["sources"][i["source_ref"]][1] for i in context["request"]["inputs"]]
    return {"algorithm": context["config"].snapshot,
            "sources": {s.source_namespace: s.snapshot() for s in settings}}


def matching_snapshots(context):
    from app.services.analysis import ALGORITHM_VERSION
    from app.utils.stable_id import content_digest
    expected = content_digest(expected_snapshot(context))
    inputs = sorted(context["request"]["inputs"], key=lambda i: (i["source_ref"], i["path"]))
    candidates = []
    for path in sorted((context["root"] / "data/processed").glob("ana_*/run.json")):
        try:
            run = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            # Never silently fall back from a corrupt execution marker.
            raise ValueError("snapshot_invalid: unreadable run marker " + str(path)) from exc
        if (run.get("config_hash") == expected and run.get("inputs") == inputs
                and run.get("algorithm_version") == ALGORITHM_VERSION):
            candidates.append(run)
    return sorted(candidates, key=lambda r: (r.get("created_at", ""), r["analysis_id"]), reverse=True)


def choose_snapshot(context, explicit=None):
    if explicit:
        return explicit
    candidates = matching_snapshots(context)
    if not candidates:
        return None
    candidate = candidates[0]
    if candidate["status"] != "completed" or not candidate["is_complete"]:
        raise ValueError("snapshot_invalid: latest matching run is " + candidate["status"])
    return candidate["analysis_id"]


def validate_snapshot(context, identity, *, force=False):
    from app.services.analysis import ALGORITHM_VERSION
    from app.services.storage import MODELS, SnapshotStore, file_digest
    from app.utils.stable_id import content_digest
    from demo_support import collect, save
    started = time.perf_counter()
    store = SnapshotStore(context["root"], identity)
    try:
        record, _, manifest = store.read_metadata()
        if record.status.value != "completed" or not record.is_complete:
            raise ValueError("analysis_not_completed")
        if record.schema_version != "1.0" or record.algorithm_version != ALGORITHM_VERSION:
            raise ValueError("schema_or_algorithm_version_mismatch")
        if record.config_snapshot != expected_snapshot(context) or record.mapping_digest != context["config"].mapping_digest:
            raise ValueError("configuration_or_mapping_mismatch")
        summary = manifest["summary"]
        inputs = sorted(context["request"]["inputs"], key=lambda i: (i["source_ref"], i["path"]))
        if summary["inputs"] != inputs or len(summary["input_files"]) != len(inputs):
            raise ValueError("input_reference_mismatch")
        if [{k: f[k] for k in ("source", "source_ref", "path")} for f in summary["input_files"]] != inputs:
            raise ValueError("input_file_inventory_mismatch")
        for item in summary["input_files"]:
            if file_digest(context["root"] / item["path"]) != item["sha256"]:
                raise ValueError("input_changed:" + item["path"])
        required = {k + ext for k in MODELS for ext in (".parquet", ".jsonl")} | {"analysis.json", "run.json"}
        if set(manifest["files"]) != required or not all((store.domain / name).is_file() for name in required):
            raise ValueError("required_artifact_missing")
        if json.loads((store.domain / "run.json").read_text(encoding="utf-8")) != summary:
            raise ValueError("run_manifest_mismatch")
        backend = {p.relative_to(context["root"]).as_posix(): file_digest(p)
                   for p in sorted((context["root"] / "backend/app").rglob("*.py"))}
        binding = {"analysis_id": identity, "snapshot_identity": manifest["execution"]["snapshot_identity"],
                   "manifest_sha256": file_digest(store.details / "manifest.json"), "backend_files": backend}
        receipts = context["root"] / "outputs/task09/validated_snapshots"
        receipts.mkdir(parents=True, exist_ok=True)
        receipt_path = receipts / (identity + ".json")
        receipt = None
        if receipt_path.exists() and not force:
            cached = json.loads(receipt_path.read_text(encoding="utf-8"))
            payload = {k: v for k, v in cached.items() if k != "receipt_digest"}
            if cached.get("receipt_digest") != content_digest(payload):
                raise ValueError("validation_receipt_corrupted")
            if cached.get("binding") == binding:
                receipt = cached
        reused = receipt is not None
        if receipt is None:
            # Existing collect verifies every formal object; use authoritative
            # hashed Parquet rather than the unmanifested DuckDB working file.
            _, _, _, identities = collect(context, identity, parquet=True)
            payload = {"binding": binding, "identities": identities, "status": "validated",
                       "verifier": "SnapshotStore.validate_reconstruction(parquet=True)"}
            receipt = {**payload, "receipt_digest": content_digest(payload)}
            save(receipt_path, receipt)
        return store, record, summary, receipt["identities"], {
            "status": "validated", "receipt_reused": reused,
            "duration_seconds": time.perf_counter() - started,
            "snapshot_identity": binding["snapshot_identity"], "manifest_sha256": binding["manifest_sha256"],
            "receipt_ref": receipt_path.relative_to(context["root"]).as_posix()}
    except (KeyError, ValueError, OSError) as exc:
        raise ValueError("snapshot_invalid: " + str(exc)) from exc


def select_incidents(root, identity):
    """A singleton, B most members, C richest entities. Lexical ID ties.

    Selection reads production tables only; no labels or generated AI answers.
    """
    from app.services.queries import QueryService
    q = QueryService(root)
    store = q.ready(identity)
    selected = []
    with q.connection() as db:
        sql = ("SELECT object_id, json_array_length(payload, '$.alert_ids') AS members, "
               "json_array_length(payload, '$.entity_ids') AS richness FROM read_parquet(?) ")
        for label, where, order in (("A", "members = 1", "object_id"),
                                    ("B", "members > 1", "members DESC, richness DESC, object_id"),
                                    ("C", "true", "richness DESC, members DESC, object_id")):
            ids = [i["incident_id"] for i in selected if i["incident_id"] is not None]
            row = db.execute(sql + "WHERE " + where + " AND object_id NOT IN (SELECT unnest(?)) ORDER BY " + order + " LIMIT 1",
                [q.table(store, "incidents"), ids]).fetchone()
            if row:
                selected.append({"label": label, "incident_id": row[0], "member_count": row[1], "entity_count": row[2],
                    "selection_rule": where + "; " + order})
            else:
                selected.append({"label": label, "incident_id": None, "status": "not_available",
                                 "selection_rule": where + "; " + order})
    return selected


def verify_http(root, identity, selection, get):
    """Representative API timing and claim/ATT&CK/evidence closure."""
    from app.ai.explanation import load_context
    from app.ai.grounding import make_finding
    from app.models import AIClaim
    from app.models.base import resolve_pointer
    from app.services.queries import QueryService
    from app.utils.stable_id import id_for
    q = QueryService(root)
    samples, results = [], []
    def call(name, path, method="GET", statuses=(200,)):
        start = time.perf_counter()
        status, body = get(path, method)
        samples.append({"api": name, "seconds": time.perf_counter()-start, "http_status": status})
        if status not in statuses:
            raise ValueError(f"real_smoke_failed:{name}:HTTP {status}")
        return body
    detail = call("analysis_summary", "/api/v1/analyses/" + identity)
    listing = call("incident_list", "/api/v1/incidents?analysis_id=" + identity)
    if listing["total"] != detail["counts"]["incident_count"]:
        raise ValueError("incident_count_mismatch")
    totals = dict(generated_claims=0, verified_claims=0, rejected_claims=0, rejected_mappings=0,
                  unsupported_formal_claims=0, broken_evidence_references=0, attack_mappings=0)
    for chosen in selection:
        iid = chosen["incident_id"]
        if iid is None:
            continue
        prefix = f"/api/v1/incidents/{iid}"
        scope = "?analysis_id=" + identity
        inc = call("incident_detail", prefix + scope)
        chain_body = call("chain", prefix + "/chain" + scope)
        chain = chain_body["chain"]
        if inc["analysis_id"] != identity or chain_body["analysis_id"] != identity or chain["incident_id"] != iid:
            raise ValueError("analysis_scope_mismatch")
        incident = inc["incident"]
        alerts = {}
        for aid in incident["alert_ids"]:
            body = call("evidence", "/api/v1/alerts/" + aid + scope)
            alert = body["alert"]
            if body["analysis_id"] != identity or alert["alert_id"] != aid:
                raise ValueError("evidence_scope_mismatch")
            for provenance in alert["field_provenance"].values():
                resolve_pointer(alert["raw_alert"], provenance["raw_pointer"])
            alerts[aid] = alert
        if {a for n in chain["nodes"] for a in n["alert_ids"]} != set(alerts):
            raise ValueError("node_closure_failed")
        call("timeline", prefix + "/timeline" + scope)
        response = call("explain", prefix + "/explain" + scope, "POST", (200, 409))
        report = response.get("report_json")
        context = load_context(q, identity, iid)
        if (not report or response["grounding_status"] != "validated" or report["analysis_id"] != identity
                or report["incident_id"] != iid or report["chain_id"] != chain["chain_id"]
                or report["input_digest"] != context.input_digest):
            raise ValueError("formal_report_scope_or_grounding_failed")
        nodes, edges = {n["node_id"] for n in chain["nodes"]}, {e["edge_id"] for e in chain["edges"]}
        claims = {}
        for data in report["claims"]:
            claim = AIClaim.model_validate(data)
            if (claim.grounding_status.value != "validated" or id_for("AIClaim", claim) != claim.claim_id
                    or not set(claim.alert_ids) <= alerts.keys() or not set(claim.node_ids) <= nodes
                    or not set(claim.edge_ids) <= edges):
                totals["broken_evidence_references"] += 1
            if claim.kind.value == "fact":
                finding = make_finding(context.data, data["propositions"])
                supported = (finding["statement"] == claim.text and set(finding["alert_refs"]) <= set(claim.alert_ids)
                    and set(finding["node_refs"]) <= set(claim.node_ids) and set(finding["edge_refs"]) <= set(claim.edge_ids))
                for proposition in data["propositions"]:
                    table = {"alert": "alerts", "node": "nodes", "chain_edge": "edges", "correlation_edge": "correlations"}[proposition["subject_type"]]
                    supported &= context.data["facts"][table][proposition["subject_id"]][proposition["field"]] == proposition["value"]
                if not supported:
                    totals["unsupported_formal_claims"] += 1
            claims[claim.claim_id] = data
        for ref in report["evidence_refs"]:
            resolve_pointer(alerts[ref["alert_id"]]["raw_alert"], ref["pointer"])
        for technique in report["attack_techniques"]:
            claim = claims[technique["claim_id"]]
            if technique["mapping_status"] != "validated" or claim["kind"] != "attack_mapping":
                raise ValueError("attack_mapping_grounding_failed")
            for ref in technique["evidence_refs"]:
                resolve_pointer(alerts[ref["alert_id"]]["raw_alert"], ref["pointer"])
        rejected = len(response["rejected_claims"])
        totals["verified_claims"] += len(claims)
        totals["rejected_claims"] += rejected
        totals["rejected_mappings"] += len(response["rejected_mappings"])
        totals["generated_claims"] += len(claims) + rejected
        totals["attack_mappings"] += len(report["attack_techniques"])
        saved = call("persisted_report", prefix + "/explanation" + scope)
        if saved["result"]["report_json"] != report:
            raise ValueError("persisted_report_mismatch")
        results.append({**chosen, "node_count": len(nodes), "edge_count": len(edges),
            "closure": "passed", "generation_status": response["generation_status"],
            "result_origin": response["result_origin"], "verified_claims": len(claims),
            "rejected_claims": rejected, "attack_mappings": len(report["attack_techniques"]),
            "url_query": f"?analysis_id={identity}&incident_id={iid}"})
    if totals["unsupported_formal_claims"] or totals["broken_evidence_references"]:
        raise ValueError("formal_claim_integrity_failed:" + json.dumps(totals))
    return {"status": "passed", "counts": detail["counts"], "incidents": results, "claim_statistics": totals,
            "claim_scope": "only selected Demo A/B/C; generated includes deterministic fallback, not necessarily LLM",
            "api_samples": samples, "edge_closure": "not_applicable_real_dataset" if not detail["counts"]["chain_edge_count"] else "validated_snapshot",
            "attack_mapping_closure": "passed" if totals["attack_mappings"] else "not_applicable_selected_real_incidents",
            "ground_truth_used": False}


def main():
    from demo_support import preflight, truth_guard, http_get, save
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analysis-id", required=True)
    parser.add_argument("--url", required=True, help="Local API URL printed by scripts/demo.py")
    parser.add_argument("--browser-tests", action="store_true", help="Run real and separately labeled synthetic browser acceptance")
    parser.add_argument("--browser-executable", help="Optional installed Chromium executable")
    args = parser.parse_args()
    if not args.url.startswith("http://127.0.0.1:"):
        parser.error("--url must be the local demo API")
    with truth_guard(ROOT):
        context = preflight(ROOT)
        validate_snapshot(context, args.analysis_id)
        selected = select_incidents(ROOT, args.analysis_id)
        result = verify_http(ROOT, args.analysis_id, selected,
                             lambda path, method="GET": http_get(args.url, path, method))
        save(ROOT / "outputs/task09/real_smoke.json", result)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.browser_tests:
        import os
        import subprocess
        output = ROOT / "outputs/task09"
        config = output / "playwright.config.mjs"
        config.write_text("export default " + json.dumps({
            "testDir": str(ROOT / "frontend"), "testMatch": ["e2e/workbench.spec.ts", "src/__tests__/demo.browser.spec.ts"],
            "timeout": 180000, "expect": {"timeout": 30000}, "workers": 1,
            "reporter": [["list"], ["junit", {"outputFile": str(output / "browser.xml")}]],
            "outputDir": str(output / "browser-artifacts"), "use": {
                "baseURL": args.url, "viewport": {"width": 1440, "height": 1050},
                "screenshot": "only-on-failure", "trace": "retain-on-failure",
                "launchOptions": {"executablePath": args.browser_executable} if args.browser_executable else {}}}) + ";\n", encoding="utf-8")
        environment = {**os.environ, "TRACEBACK_ANALYSIS_ID": args.analysis_id}
        started = time.perf_counter()
        with (output / "browser.log").open("w", encoding="utf-8") as log:
            process = subprocess.run(["node", "node_modules/@playwright/test/cli.js", "test", "--config", str(config)],
                cwd=ROOT / "frontend", env=environment, stdout=log, stderr=subprocess.STDOUT)
        save(output / "browser_execution.json", {"exit_code": process.returncode,
            "duration_seconds": time.perf_counter()-started, "analysis_id": args.analysis_id, "url": args.url})
        return process.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
