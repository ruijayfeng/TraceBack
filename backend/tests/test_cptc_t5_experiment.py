from evaluation.framework.preformula_baseline.boundary import development_config, development_cptc, verify_historical_inventory, verify_current
"""Single-input boundary and formal reconstruction replay contracts."""
from pathlib import Path
import sys
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'scripts'))
from cptc_2018_t5 import INPUT, input_guard, semantic_digest
from cptc_2018_step3a import load_frozen_config
from app.chains.assembly import run_reconstruction
from app.correlation.edges import run_correlation
from test_correlation_score import inputs, parent_child


@pytest.mark.parametrize('partition', ['t1', 't2', 't7', 't8', 't9'])
def test_other_real_partition_open_rejected(partition):
    with pytest.raises(PermissionError, match='only_t5'):
        input_guard('open', (str(INPUT.with_name('suricata_alert_'+partition+'.json.gz')), 'r'))


def test_t5_open_allowed():
    input_guard('open', (str(INPUT), 'r'))


def test_production_reconstruction_replay_covers_singletons_and_evidence():
    index, settings = inputs(parent_child())
    config = development_config()[0]
    alerts, entities = list(index.alerts.values()), list(index.entities.values())
    cor = run_correlation(alerts, [], entities, config, settings)
    a = run_reconstruction(alerts, [], entities, cor.edges, config, settings, upstream_record=cor.record)
    b = run_reconstruction(list(reversed(alerts)), [], entities, list(reversed(cor.edges)), config, settings,
                           upstream_record=cor.record)
    assert a.grounding.valid and b.grounding.valid
    assert semantic_digest(a.incidents) == semantic_digest(b.incidents)
    assert semantic_digest(a.chains) == semantic_digest(b.chains)
    assert sorted(i for incident in a.incidents for i in incident.alert_ids) == sorted(index.alerts)
