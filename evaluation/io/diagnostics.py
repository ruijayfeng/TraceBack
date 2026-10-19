"""Bounded streaming extraction of existing unrounded member diagnostics."""

from collections import Counter
import csv
import json
import math
from pathlib import Path

import duckdb

from app.services.storage import file_digest
from evaluation.ablation.experiments import rarity_disabled_evaluator


VALUES = ("time", "entity", "relation", "behavior", "source", "conflict", "duplicate")
MEMBER_COLUMNS = ("rep_left", "rep_right", "left_alert_id", "right_alert_id", "score", "raw_total", "valid",
                  "source_independence", "rejection_codes", "diagnostic_offset", "no_rarity_score") + VALUES + tuple("c_" + v for v in VALUES)


def connect_database(destination):
    db = duckdb.connect(str(Path(destination) / "evaluation.duckdb"))
    db.execute("SET memory_limit='512MB'")
    db.execute("SET threads=1")
    db.execute("SET preserve_insertion_order=false")
    return db


def extract_scores(snapshot, destination, progress=lambda _: None):
    destination = Path(destination)
    input_path = snapshot.store.details / "diagnostics.jsonl"
    cache_path = destination / "score_snapshot.json"
    binding = {"analysis_id": snapshot.record.analysis_id, "diagnostics_sha256": snapshot.manifest["diagnostics_digest"],
               "extractor_version": "evaluation-score-extract-v1", "extractor_sha256": file_digest(Path(__file__)),
               "entity_ablation_sha256": file_digest(Path(__file__).parents[1]/"ablation/experiments.py")}
    db = connect_database(destination)
    if cache_path.exists():
        cache = json.loads(cache_path.read_text(encoding="utf-8"))
        if cache["binding"] == binding and all(file_digest(destination / f) == d for f, d in cache["files"].items()):
            _load_tables(db, destination)
            return db, cache["summary"]
    no_rarity = rarity_disabled_evaluator(snapshot)
    weights = snapshot.config.algorithm.score.weights.model_dump()
    weight = weights["entity"]
    member_csv, candidate_csv = destination / "members.tmp.csv", destination / "candidates.tmp.csv"
    rejection, hard, source = Counter(), Counter(), Counter()
    member_count = candidate_count = decision_count = accepted = 0
    active, active_members = None, set()
    with input_path.open("rb") as source_file, member_csv.open("w", encoding="utf-8", newline="") as mh, candidate_csv.open("w", encoding="utf-8", newline="") as ch:
        mw, cw = csv.writer(mh), csv.writer(ch)
        mw.writerow(MEMBER_COLUMNS)
        cw.writerow(("rep_left", "rep_right", "admission_metadata", "diagnostic_offset"))
        offset = 0
        for line in source_file:
            # Production canonical writer has compact JSON. Also support spaced
            # JSON from other validated writers; stage tests cannot match nested fields.
            row = None
            if any(token in line for stage in ("candidate", "member_score", "correlation_decision")
                   for token in (f'"stage":"{stage}"'.encode(), f'"stage": "{stage}"'.encode())):
                row = json.loads(line)
            if row and row.get("stage") == "candidate":
                pair = row["support_key"]
                if active is not None:
                    raise ValueError("candidate_diagnostic_unclosed")
                active = pair
                active_members = set()
                cw.writerow((*pair, json.dumps(row, separators=(",", ":"), ensure_ascii=False), offset))
                candidate_count += 1
            elif row and row.get("stage") == "member_score":
                pair, members = row["support_key"], row["support_pair"]
                if pair != active or any(snapshot.owner.get(i) != r for i, r in zip(members, pair)):
                    raise ValueError("member_score_group_reference_mismatch")
                if tuple(members) in active_members:
                    raise ValueError("duplicate_member_score")
                active_members.add(tuple(members))
                values, contributions, raw, score = row["values"], row["contributions"], row["raw_total"], row["score"]
                if set(values) != set(VALUES) or set(contributions) != set(VALUES):
                    raise ValueError("member_component_schema_mismatch")
                for k in VALUES:
                    expected = weights[k] * values[k] * (-1 if k in {"conflict","duplicate"} else 1)
                    if not math.isfinite(values[k]) or not 0 <= values[k] <= 1 or not math.isclose(contributions[k],expected,abs_tol=1e-12):
                        raise ValueError("member_contribution_config_mismatch")
                if not math.isclose(sum(contributions.values()), raw, abs_tol=1e-12) or not math.isclose(score, max(0, min(1, raw)), abs_tol=1e-12):
                    raise ValueError("member_score_not_recomputable")
                if row["valid"] != (not row["rejection_codes"]):
                    raise ValueError("member_guard_state_mismatch")
                rarity_score = max(0.0, min(1.0, raw - contributions["entity"] + weight * no_rarity(*members)))
                mw.writerow((*pair, *members, score, raw, row["valid"], row["source_independence"],
                             json.dumps(row["rejection_codes"]), offset, rarity_score,
                             *(values[k] for k in VALUES), *(contributions[k] for k in VALUES)))
                source.update([row["source_independence"]])
                hard.update(row["rejection_codes"])
                member_count += 1
            elif row and row.get("stage") == "correlation_decision":
                if row["support_key"] != active:
                    raise ValueError("correlation_decision_without_candidate")
                if len(active_members) != len(snapshot.groups[active[0]]) * len(snapshot.groups[active[1]]):
                    raise ValueError("candidate_member_verification_incomplete")
                active = None
                accepted += row["decision"] == "accept"
                rejection.update([row["rule_id"]])
                decision_count += 1
                if decision_count % 100000 == 0:
                    progress({"stage": "extract_existing_scores", "candidate_count": decision_count})
            offset += len(line)
    if active is not None or candidate_count != decision_count or candidate_count != snapshot.record.metrics.candidate_pair_count:
        raise ValueError("score_snapshot_candidate_count_mismatch")
    expected_edges = sum(1 for _ in snapshot.records("correlation_edges"))
    if accepted != expected_edges:
        raise ValueError("score_snapshot_edge_count_mismatch")
    types = {"rep_left": "VARCHAR", "rep_right": "VARCHAR", "left_alert_id": "VARCHAR", "right_alert_id": "VARCHAR",
             "valid": "BOOLEAN", "source_independence": "VARCHAR", "rejection_codes": "VARCHAR", "diagnostic_offset": "BIGINT"}
    types = {k: types.get(k, "DOUBLE") for k in MEMBER_COLUMNS}
    db.execute("CREATE OR REPLACE TABLE member_scores AS SELECT * FROM read_csv(?,header=true,columns=?)", [str(member_csv), types])
    db.execute("ALTER TABLE member_scores ADD COLUMN ground_truth_available BOOLEAN DEFAULT false")
    db.execute("ALTER TABLE member_scores ADD COLUMN ground_truth BOOLEAN DEFAULT NULL")
    db.execute("CREATE OR REPLACE TABLE admissions AS SELECT * FROM read_csv(?,header=true,columns=?)", [str(candidate_csv),
        {"rep_left": "VARCHAR", "rep_right": "VARCHAR", "admission_metadata": "VARCHAR", "diagnostic_offset": "BIGINT"}])
    _build_selected(db, snapshot)
    actual_selected_edges = db.execute("SELECT count(*) FROM selected_scores WHERE score>=?",[snapshot.config.algorithm.score.correlation_threshold]).fetchone()[0]
    if actual_selected_edges != accepted:
        raise ValueError("selected_scores_disagree_with_production_decisions")
    for table in ("member_scores", "admissions", "selected_scores"):
        db.execute(f"COPY {table} TO ? (FORMAT PARQUET, ROW_GROUP_SIZE 8192)", [str(destination / (table + ".parquet"))])
    summary = {"candidate_count": candidate_count, "member_pair_count": member_count, "accepted_edge_count": accepted,
               "rejection_distribution": dict(sorted(rejection.items())), "member_guard_rejections": dict(sorted(hard.items())),
               "source_independence_distribution": dict(sorted(source.items()))}
    files = {t + ".parquet": file_digest(destination / (t + ".parquet")) for t in ("member_scores", "admissions", "selected_scores")}
    cache_path.write_text(json.dumps({"binding": binding, "summary": summary, "files": files}, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    member_csv.unlink()
    candidate_csv.unlink()
    return db, summary


def _build_selected(db, snapshot):
    # Winner ordering mirrors production: maximum valid full member score, then
    # source timestamp, target timestamp, source ID, target ID. No feature maxima.
    db.execute("CREATE OR REPLACE TABLE alert_times(alert_id VARCHAR,time_us BIGINT)")
    db.executemany("INSERT INTO alert_times VALUES (?,?)", [(i, a["time_us"]) for i, a in snapshot.alerts.items()])
    db.execute("CREATE OR REPLACE TABLE selected_scores AS SELECT m.* "
        "FROM member_scores m JOIN alert_times l ON m.left_alert_id=l.alert_id JOIN alert_times r ON m.right_alert_id=r.alert_id "
        "WHERE valid QUALIFY row_number() OVER(PARTITION BY rep_left,rep_right ORDER BY score DESC,l.time_us,r.time_us,left_alert_id,right_alert_id)=1")
    count = db.execute("SELECT count(*) FROM admissions a LEFT JOIN (SELECT rep_left,rep_right,count(*) n FROM member_scores GROUP BY ALL) m USING(rep_left,rep_right) WHERE m.n IS NULL").fetchone()[0]
    if count:
        raise ValueError("candidate_has_no_member_scores")


def _load_tables(db, destination):
    for table in ("member_scores", "admissions", "selected_scores"):
        kind = db.execute("SELECT table_type FROM information_schema.tables WHERE table_name=?",[table]).fetchone()
        if kind:
            db.execute(f"DROP {'VIEW' if kind[0]=='VIEW' else 'TABLE'} {table}")
        path = str(destination / (table + ".parquet")).replace("'", "''")
        db.execute(f"CREATE OR REPLACE VIEW {table} AS SELECT * FROM read_parquet('{path}')")


def score_distribution(db, threshold):
    n, minimum, maximum, mean, p50, p90, p99, above = db.execute(
        "SELECT count(*),min(score),max(score),avg(score),quantile_cont(score,.5),quantile_cont(score,.9),quantile_cont(score,.99),count(*) FILTER(WHERE score>=?) FROM selected_scores", [threshold]).fetchone()
    valid = n
    total, invalid, max_member = db.execute("SELECT count(*),count(*) FILTER(WHERE NOT valid),max(score) FROM member_scores").fetchone()
    values = db.execute("SELECT " + ",".join(f"max({v}),avg({v}),count(*) FILTER(WHERE {v}>0)" for v in VALUES) + " FROM member_scores").fetchone()
    return {"scope": "all admitted candidates; selected highest valid complete member pair", "valid_candidate_count": valid,
            "minimum": minimum, "maximum": maximum, "mean": mean, "p50": p50, "p90": p90, "p99": p99,
            "production_threshold": threshold, "valid_candidates_at_or_above_threshold": above,
            "member_pair_count": total, "invalid_member_pair_count": invalid, "maximum_member_score": max_member,
            "components": {v: {"max": values[3*i], "mean": values[3*i+1], "nonzero_member_count": values[3*i+2]} for i, v in enumerate(VALUES)},
            "positive_distribution": {"status": "unavailable", "reason": "no_pair_labels"},
            "negative_distribution": {"status": "unavailable", "reason": "no_pair_labels"}}
