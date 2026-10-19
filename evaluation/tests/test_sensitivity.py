import pytest

from evaluation.sensitivity.experiments import threshold_counts


def test_threshold_monotonic_unrounded_boundary():
    rows = threshold_counts([.3,.6499999,.65,.6500001,.8],[.8,.65,.6,.3])
    assert [r["predicted_edge_count"] for r in rows] == [5,4,3,1]
    assert threshold_counts([], [.65])[0]["predicted_edge_count"] == 0


@pytest.mark.parametrize("value", [float("nan"),-1,2])
def test_invalid_threshold(value):
    with pytest.raises(ValueError):
        threshold_counts([.5],[value])
