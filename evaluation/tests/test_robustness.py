import pytest

from evaluation.robustness.experiments import NoiseConfig, noise_plan, run_noise


def test_noise_plan_fixed_seed_nested_additions_no_duplicates():
    config = NoiseConfig(10,(0,.1,.25,.5),42)
    first = noise_plan([str(i) for i in range(100)],config)
    assert first == noise_plan([str(i) for i in reversed(range(100))],config)
    assert set(first[-1]["base_representatives"]).isdisjoint(first[-1]["added_representatives"])
    assert set(first[1]["added_representatives"]) <= set(first[-1]["added_representatives"])


def test_real_function_noise_predictions_frozen_and_input_unchanged(production_snapshot,tmp_path):
    destination = tmp_path/"outputs/evaluation/noise"
    destination.mkdir(parents=True)
    rows = run_noise(production_snapshot,destination,NoiseConfig(2,(0,.5,1),42))
    assert len(rows) == 3
    assert all(r["status"] == "completed" and r["raw_facts_unchanged"] for r in rows)
    assert [r["input_alert_count"] for r in rows] == [2,3,4]
    again = run_noise(production_snapshot,destination,NoiseConfig(2,(0,.5,1),42))
    assert rows == again
    fresh_destination = tmp_path/"outputs/evaluation/noise_fresh"
    fresh_destination.mkdir(parents=True)
    fresh = run_noise(production_snapshot,fresh_destination,NoiseConfig(2,(0,.5,1),42))
    stable = lambda results: [{k:v for k,v in r.items() if k not in {"runtime_seconds","process_peak_memory_mb"}} for r in results]
    assert stable(rows) == stable(fresh)
    production_snapshot.assert_unchanged()


@pytest.mark.parametrize("ratios", [(0,0),(1,),(-.1,0),(0,float("nan"))])
def test_invalid_noise_config(ratios):
    with pytest.raises(ValueError):
        NoiseConfig(10,ratios,42)
