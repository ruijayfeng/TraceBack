"""Read-only binding of Task 06 scores; never open its writable DuckDB cache."""

from collections import Counter
import gzip
import io
import json
from pathlib import Path
import csv
from tempfile import TemporaryDirectory

import duckdb

from app.correlation.candidates import CandidateGenerator
from app.services.storage import file_digest
from evaluation.io.diagnostics import VALUES


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                   indent=2, allow_nan=False) + "\n", encoding="utf-8")


def bind_scores(snapshot, cache):
    """Cache hashes and diagnostic binding must both match the verified snapshot."""
    cache = Path(cache)
    metadata = json.loads((cache / "score_snapshot.json").read_text(encoding="utf-8"))
    binding = metadata["binding"]
    if (binding["analysis_id"] != snapshot.record.analysis_id
            or binding["diagnostics_sha256"] != snapshot.manifest["diagnostics_digest"]):
        raise ValueError("score_cache_snapshot_mismatch")
    root = Path(__file__).resolve().parents[2]
    if (binding["extractor_sha256"] != file_digest(root / "evaluation/io/diagnostics.py")
            or binding["entity_ablation_sha256"] != file_digest(root / "evaluation/ablation/experiments.py")):
        raise ValueError("score_cache_extractor_changed")
    hashes = {"score_snapshot.json": file_digest(cache / "score_snapshot.json"), **metadata["files"]}
    for name, digest in hashes.items():
        if file_digest(cache / name) != digest:
            raise ValueError("score_cache_hash_mismatch:" + name)
    db = duckdb.connect()  # in-memory; existing evaluation.duckdb stays unopened
    db.execute("SET threads=1")
    db.execute("SET memory_limit='1536MB'")
    db.execute("SET preserve_insertion_order=false")
    for table in ("member_scores", "selected_scores", "admissions"):
        path = str(cache / (table + ".parquet")).replace("'", "''")
        db.execute(f"CREATE VIEW {table} AS SELECT * FROM read_parquet('{path}')")
    n, unique_n = db.execute("SELECT count(*),count(DISTINCT (rep_left,rep_right)) FROM admissions").fetchone()
    if n != unique_n or n != snapshot.record.metrics.candidate_pair_count:
        raise ValueError("admission_count_mismatch")
    selected_count,selected_unique = db.execute("SELECT count(*),count(DISTINCT(rep_left,rep_right)) FROM selected_scores").fetchone()
    if selected_count != n or selected_unique != n:
        raise ValueError("diagnostic_requires_all_candidates_have_valid_winner")
    # Revalidate every unrounded decomposition with the actual frozen weights.
    weights = snapshot.config.algorithm.score.weights.model_dump()
    failures = []
    for k in VALUES:
        signed = weights[k] * (-1 if k in {"conflict", "duplicate"} else 1)
        failures.extend((f"abs(c_{k}-({signed!r})*{k})>1e-12", f"{k}<0 OR {k}>1"))
    failures.extend(("abs(raw_total-(" + "+".join("c_"+k for k in VALUES) + "))>1e-12",
                     "abs(score-greatest(0,least(1,raw_total)))>1e-12",
                     "valid != (json_array_length(rejection_codes)=0)"))
    if db.execute("SELECT count(*) FROM member_scores WHERE " + " OR ".join("("+s+")" for s in failures)).fetchone()[0]:
        raise ValueError("production_decomposition_inconsistent")
    # Winner membership, full G1 x G2 completeness and deterministic tie order.
    ids = sorted(snapshot.alerts)
    csv_table(db,"alert_facts",{"alert_id":"VARCHAR","time_us":"BIGINT"},
              ((i,snapshot.alerts[i]["time_us"]) for i in ids))
    reps = sorted(snapshot.groups)
    csv_table(db,"group_sizes",{"rep":"VARCHAR","n":"BIGINT"},
              ((i,len(snapshot.groups[i])) for i in reps))
    invalid = db.execute("SELECT count(*) FROM (SELECT rep_left,rep_right,count(*) n,count(DISTINCT(left_alert_id,right_alert_id)) u "
        "FROM member_scores GROUP BY ALL) m JOIN group_sizes l ON rep_left=l.rep JOIN group_sizes r ON rep_right=r.rep "
        "WHERE m.n!=l.n*r.n OR m.n!=m.u").fetchone()[0]
    db.execute("CREATE VIEW recomputed_winners AS SELECT rep_left,rep_right,left_alert_id,right_alert_id,score FROM member_scores m "
        "JOIN alert_facts l ON left_alert_id=l.alert_id JOIN alert_facts r ON right_alert_id=r.alert_id WHERE valid "
        "QUALIFY row_number() OVER(PARTITION BY rep_left,rep_right ORDER BY score DESC,l.time_us,r.time_us,left_alert_id,right_alert_id)=1")
    mismatch = db.execute("SELECT count(*) FROM recomputed_winners w FULL OUTER JOIN selected_scores s USING(rep_left,rep_right) "
        "WHERE w.left_alert_id IS DISTINCT FROM s.left_alert_id OR w.right_alert_id IS DISTINCT FROM s.right_alert_id "
        "OR w.score IS DISTINCT FROM s.score").fetchone()[0]
    if invalid or mismatch:
        raise ValueError("full_member_or_winner_inconsistent")
    return db, {"files": hashes, "binding": binding, "summary": metadata["summary"],
                "all_member_decompositions_verified": True, "all_winners_verified": True}


def csv_table(db,name,columns,rows):
    """Bounded local CSV avoids slow Python-list conversion without pandas.

    Only diagnostic tables use this helper. No production file/config is written.
    Row order never defines an ID, ranking or score.
    """
    allowed={"alert_facts","group_sizes","window_reps","temporal_group_context","gt_temporal_scores"}
    if name not in allowed:
        raise ValueError("unknown_diagnostic_table")
    with TemporaryDirectory(prefix="traceback-score-diagnostic-") as temporary:
        path=Path(temporary)/"facts.csv"
        with path.open("w",encoding="utf-8",newline="") as handle:
            writer=csv.writer(handle)
            writer.writerow(columns)
            writer.writerows(rows)
        db.execute(f"CREATE OR REPLACE TABLE {name} AS SELECT * FROM read_csv(?,header=true,columns=?)",
                   [str(path),columns])


def distribution(db, table="selected_scores", column="score", where="true"):
    if table not in {"selected_scores", "member_scores","gt_temporal_scores"} or column not in {"score", *VALUES}:
        raise ValueError("unknown_statistic")
    quantiles = (("P50", .5), ("P75", .75), ("P90", .9), ("P95", .95),
                 ("P99", .99), ("P99.5", .995), ("P99.9", .999))
    names = ["count", "min", "max", "mean", "median", "std", *(k for k, _ in quantiles)]
    sql = ["count(*)", f"min({column})", f"max({column})", f"avg({column})",
           f"quantile_cont({column},.5)", f"stddev_pop({column})",
           *(f"quantile_cont({column},{q})" for _, q in quantiles)]
    return dict(zip(names, db.execute("SELECT " + ",".join(sql) + f" FROM {table} WHERE {where}").fetchone()))


def member_distribution(db, maxima, weights, table="selected_scores"):
    rows = []
    for k in VALUES:
        row = {"member": k, **distribution(db, table, k), "weight": weights[k], "theoretical_max": maxima[k]}
        nz, atmax, contribution = db.execute(f"SELECT count(*) FILTER(WHERE {k}>0),count(*) FILTER(WHERE {k}=?),avg(c_{k}) FROM {table}", [maxima[k]]).fetchone()
        row.update(nonzero_count=nz, nonzero_ratio=nz/row["count"], at_theoretical_max_count=atmax,
                   mean_signed_contribution=contribution)
        rows.append(row)
    return rows


def threshold_scan(db, threshold):
    rows = []
    for delta in (0, .01, .02, .05, .10):
        t = threshold - delta  # compare unrounded scores; never mutate a config
        members = db.execute("SELECT count(*) FROM member_scores WHERE score>=?", [t]).fetchone()[0]
        passing = db.execute("SELECT count(*) FROM (SELECT rep_left,rep_right,max(score) score FROM member_scores GROUP BY ALL) WHERE score>=?", [t]).fetchone()[0]
        admissible = db.execute("SELECT count(*) FROM selected_scores WHERE score>=?", [t]).fetchone()[0]
        rows.append({"delta": delta, "threshold": t, "score_passing_member_pair": members,
                     "score_passing_pair": passing, "actual_admissible_pair": admissible,
                     "remaining_guard_failed_pair": passing-admissible,
                     "creates_production_edges": False,
                     "direction_gate": "not_applicable_to_undirected_CorrelationEdge"})
    return rows


def blocking_reasons(db, threshold):
    n = db.execute("SELECT count(*) FROM selected_scores").fetchone()[0]
    guard = Counter()
    for codes, count in db.execute("SELECT rejection_codes,count(*) FROM member_scores GROUP BY ALL ORDER BY ALL").fetchall():
        for code in json.loads(codes):
            guard[code] += count
    below = db.execute("SELECT count(*) FROM selected_scores WHERE score<?", [threshold]).fetchone()[0]
    combos = db.execute("SELECT rejection_codes,score<? below,count(*) FROM member_scores GROUP BY ALL ORDER BY ALL", [threshold]).fetchall()
    def row(reason, count):
        return {"reason": reason, "pair_count": count, "ratio": count/n}
    return {"production_order": ["score_pair hard conflict + missing_non_time_support", "select highest valid full member pair",
                                  "no_valid_member_pair", "below_correlation_threshold", "CorrelationEdge schema validation"],
            "candidate_count": n, "member_pair_count": db.execute("SELECT count(*) FROM member_scores").fetchone()[0],
            "first_blocking_reason": [row("below_correlation_threshold", below), row("no_valid_member_pair", 0)],
            "all_failed_conditions": [row("below_correlation_threshold", below),
                                      *(row(k, v) for k, v in sorted(guard.items()))],
            "member_failure_combinations": [{"conditions": [*json.loads(codes), *(["below_correlation_threshold"] if low else [])],
                                              "member_pair_count": count} for codes, low, count in combos],
            "hard_guard_failure_count": sum(guard.values()),
            "relation_direction": "No standalone CorrelationEdge relation/direction gate; relation affects score. Chain gates run downstream.",
            "schema_validation": "not reached in baseline; offline threshold replay uses production model validation"}


def read_at(path, offset):
    with Path(path).open("rb") as handle:
        handle.seek(offset)
        return json.loads(handle.readline())


def potential_masks(index, config, scorer, path):
    """Observe full-input production range retrieval before reading any GT.

    No candidate policy is altered or executed. retrieve(limit=0) preserves its
    exact potential mask, but emits no nominations. Current supported fast path
    is proven to have no relation or independence channel; reject other inputs.
    """
    if scorer.has_independence_mappings or any(a.relations for a in index.alerts.values()):
        raise ValueError("potential_mask_requires_no_relation_or_source_channel")
    generator = CandidateGenerator(index, config, scorer)
    masks, channel_counts = [], Counter()
    with Path(path).open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with io.TextIOWrapper(compressed, encoding="utf-8", newline="\n") as output:
                for rep in index.representatives:
                    channels = {}
                    for aid in index.groups[rep]:
                        mask, _, _ = generator.retrieve(aid, "time_only", index.time, 0)
                        channels["time_only"] = channels.get("time_only", 0) | mask
                        for eid in index.alerts[aid].entity_ids:
                            kind = index.entities[eid].type.value
                            mask, _, _ = generator.retrieve(aid, kind, index.by_entity[eid], 0, eid)
                            channels[kind] = channels.get(kind, 0) | mask
                    union = 0
                    for channel, mask in channels.items():
                        union |= mask
                        channel_counts[channel] += mask.bit_count()
                    masks.append(union)
                    non_time = 0
                    for channel, mask in channels.items():
                        if channel != "time_only":
                            non_time |= mask
                    output.write(json.dumps({"representative": rep, "potential_mask_hex": hex(union),
                                             "non_time_mask_hex": hex(non_time)}, sort_keys=True) + "\n")
    return masks, {"unique_potential_pairs": sum(m.bit_count() for m in masks)//2,
                   "per_channel_unique_pairs": {k: v//2 for k,v in sorted(channel_counts.items())},
                   "scope": "all full-input representative pairs; original-member union; frozen effective windows before Top-K",
                   "mask_sha256": file_digest(path), "bit_order": "lexicographic representative ID",
                   "gt_loaded": False}
