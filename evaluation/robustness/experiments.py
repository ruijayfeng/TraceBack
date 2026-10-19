"""Truth-free real-input perturbations: fixed-seed addition of other alerts."""

from dataclasses import dataclass
import json
import math
from pathlib import Path
import random
import time

from app.chains.assembly import run_reconstruction
from app.correlation.edges import peak_memory_mb, run_correlation
from app.models import CanonicalAlert, DedupeGroup, Entity
from app.services.storage import file_digest
from app.utils.stable_id import content_digest


@dataclass(frozen=True)
class NoiseConfig:
    base_representatives: int = 512
    ratios: tuple = (0.0, 0.10, 0.25, 0.50)
    seed: int = 42

    def __post_init__(self):
        if type(self.base_representatives) is not int or self.base_representatives < 2 or type(self.seed) is not int:
            raise ValueError("invalid_noise_sampling")
        if not self.ratios or len(set(self.ratios)) != len(self.ratios) or 0 not in self.ratios or any(type(r) not in (int, float) or not math.isfinite(r) or r < 0 for r in self.ratios):
            raise ValueError("invalid_noise_ratios")


def noise_plan(representatives, config):
    reps = sorted(set(representatives))
    random.Random(config.seed).shuffle(reps)
    n = min(config.base_representatives, len(reps))
    if n + math.ceil(n * max(config.ratios)) > len(reps):
        raise ValueError("not_enough_independent_real_records_for_noise")
    base, rest = reps[:n], reps[n:]
    return [{"ratio": r, "base_representatives": sorted(base), "added_representatives": sorted(rest[:math.ceil(n*r)]),
             "seed": config.seed} for r in sorted(config.ratios)]


def run_noise(snapshot, destination, config, progress=lambda _: None):
    """Called before the runner loads GT; no GT parameter or object accepted."""
    plan = noise_plan(snapshot.groups, config)
    identity = {"prediction_identity": snapshot.identity, "noise_config": {"base_representatives": config.base_representatives,
        "ratios": list(config.ratios), "seed": config.seed}, "method": "real_unlabelled_interference_v1",
        "experiment_implementation_sha256": file_digest(Path(__file__))}
    cache_path = Path(destination) / "noise_predictions.json"
    if cache_path.exists():
        cache = json.loads(cache_path.read_text(encoding="utf-8"))
        if cache["input_binding"] == identity and cache["result_digest"] == content_digest(cache["rows"]):
            return cache["rows"]
    selected = {i for p in plan for r in p["base_representatives"] + p["added_representatives"] for i in snapshot.groups[r]}
    alerts = {a["alert_id"]: CanonicalAlert.model_validate(a) for a in snapshot.records("alerts") if a["alert_id"] in selected}
    groups = [DedupeGroup.model_validate(g) for g in snapshot.records("dedupe_groups") if set(g["alert_ids"]) <= selected]
    entities = list(snapshot.records("entities"))
    rows = []
    for p in plan:
        started = time.perf_counter()
        ids = {i for r in p["base_representatives"] + p["added_representatives"] for i in snapshot.groups[r]}
        a = [alerts[i] for i in sorted(ids)]
        g = [group for group in groups if set(group.alert_ids) <= ids]
        e = [Entity.model_validate({**entity, "alert_ids": sorted(set(entity["alert_ids"]) & ids)})
             for entity in entities if set(entity["alert_ids"]) & ids]
        before = {x.alert_id: x.raw_fingerprint for x in a}
        correlation = run_correlation(a, g, e, snapshot.config, snapshot.settings)
        reconstruction = run_reconstruction(a, g, e, correlation.edges, snapshot.config, snapshot.settings, upstream_record=correlation.record)
        if not correlation.record.is_complete or not reconstruction.record.is_complete or not reconstruction.grounding.valid:
            raise ValueError("noise_experiment_incomplete")
        if before != {x.alert_id: x.raw_fingerprint for x in a}:
            raise ValueError("noise_changed_input_facts")
        s = correlation.summary
        rows.append({"ratio": p["ratio"], "seed": config.seed, "base_representative_count": len(p["base_representatives"]),
            "added_representative_count": len(p["added_representatives"]), "input_alert_count": len(a),
            "input_alert_ids": sorted(ids), "dataset_digest": correlation.record.dataset_digest,
            "config_hash": correlation.record.config_hash, "input_plan_digest": content_digest(p),
            "potential_pair_count": s["potential_pair_stats"]["unique_potential_pairs"],
            "admitted_candidate_count": s["admitted_candidate_count"], "scored_candidate_count": s["scored_candidate_count"],
            "policy_pruned_count": s["policy_pruned_count"], "resource_truncated_count": s["resource_truncated_count"],
            "edge_count": len(correlation.edges), "incident_count": len(reconstruction.incidents),
            "chain_edge_count": sum(len(c.edges) for c in reconstruction.chains), "status": "completed",
            "runtime_seconds": time.perf_counter() - started, "process_peak_memory_mb": peak_memory_mb(),
            "scope": "fixed real-data subset; added records are unlabelled interference, not verified benign",
            "raw_facts_unchanged": True})
        progress({"stage": "noise_prediction_frozen", "ratio": p["ratio"], "input_count": len(a)})
    cache_path.write_text(json.dumps({"input_binding": identity, "rows": rows, "result_digest": content_digest(rows)}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return rows
