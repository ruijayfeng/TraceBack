from evaluation.framework.preformula_baseline.boundary import development_config, development_cptc, verify_historical_inventory, verify_current
"""Selection safety tests. Inputs created here are synthetic, never Demo data."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import json

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('demo_discovery', ROOT / 'scripts/find_demo_dataset.py')
discovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(discovery)


def test_accepted_frozen_algorithm_and_mapping_are_unchanged():
    from app.services.datasets import load_dataset
    # Historical accepted recipe; active semantic tests use the separate preformula receipt.
    receipt = json.loads((ROOT/'outputs/correlation_v4_small/FREEZE_MANIFEST.json').read_text(encoding='utf8'))
    assert verify_historical_inventory(receipt['implementation'])['status'] == 'PASS'
    assert receipt['threshold'] == .65
    assert receipt['algorithm_version'] == 'alert-correlation-v4-role-context-candidate-v1.1'


def test_continuous_window_retains_all_records_including_duplicates(tmp_path, monkeypatch):
    from app.services.datasets import load_dataset
    actual = load_dataset(ROOT, scene_id='russellmitchell', config_version='v4')
    start = '2022-01-22T12:00:00.000000Z'
    raw = [{'timestamp': t, 'rule': {'id':'synthetic'}} for t in
           ('2022-01-22T11:59:59Z', '2022-01-22T12:00:00Z',
            '2022-01-22T12:07:00Z', '2022-01-22T12:14:59.999999Z', '2022-01-22T12:15:00Z')]
    raw.insert(3, raw[2].copy())
    (tmp_path / 'input.json').write_text(json.dumps(raw), encoding='utf8')
    loaded = SimpleNamespace(config=actual.config, sources=actual.sources,
                             inputs=[{'source':'wazuh','path':'input.json'}])
    monkeypatch.setattr(discovery, 'ROOT', tmp_path)
    selected = discovery.selected_records(loaded, [start])
    assert selected[start]['wazuh'] == raw[1:5]
    assert selected[start]['aminer'] == []


def test_annotation_contamination_is_refused():
    from app.services.datasets import load_dataset
    loaded = load_dataset(ROOT, scene_id='russellmitchell', config_version='v4')
    with pytest.raises(ValueError):
        discovery.stamp({'timestamp':'2022-01-22T12:00:00Z','ground_truth':'synthetic'},
                        'wazuh', discovery.adapter(loaded,'wazuh'))


def test_audit_transport_normalizes_statistics_without_changing_values(tmp_path):
    from collections import Counter
    path = tmp_path / 'audit.json'
    discovery.atomic_json(path, {'counts':Counter({'wazuh':3}), 'pair':('a','b')})
    assert json.loads(path.read_text(encoding='utf8')) == {'counts':{'wazuh':3},'pair':['a','b']}


def test_suitability_saturates_edge_count_and_rewards_readable_incidents():
    def edge():
        return SimpleNamespace(score_breakdown=SimpleNamespace(evidence_v2=SimpleNamespace(evidence_families=['HOST','TEMPORAL'])),
            support_pair=SimpleNamespace(alert_id_src='a', alert_id_dst='b'))
    index = SimpleNamespace(owner={'a':'a','b':'b','c':'c'}, alerts={
        k:SimpleNamespace(source_type='wazuh') for k in 'abc'})
    multi = SimpleNamespace(alert_ids=['a','b'])
    singleton = SimpleNamespace(alert_ids=['c'])
    assert discovery.suitability([edge()]*20,[multi,singleton],index)[0] == discovery.suitability([edge()]*200,[multi,singleton],index)[0]
    assert discovery.suitability([edge()],[multi,singleton],index)[0] > discovery.suitability([edge()],[multi],index)[0]


def test_supplement_uses_only_inventory_and_keeps_fixed_continuous_windows(tmp_path,monkeypatch):
    start = 1642852800  # synthetic time grid, not a dataset-specific algorithm rule
    bins = {str(start+n*900):{'raw_counts':{'aminer':10,'wazuh':20}, 'fields':{'account':n}}
            for n in range(5)}
    plan = {'scenes':{'synthetic':{'bins':bins}},'windows':[{'scene':'synthetic',
        'window_start':discovery.utc_text(discovery.datetime.fromtimestamp(start+4*900,discovery.timezone.utc))}]}
    discovery.atomic_json(tmp_path/'search_plan.json',plan)
    monkeypatch.setattr(discovery,'OUT',tmp_path)
    discovery.supplemental_plan()
    supplement = json.loads((tmp_path/'supplemental_search_plan.json').read_text(encoding='utf8'))
    assert supplement['parent_plan_digest'] == discovery.content_digest(plan)
    assert all(w['raw_counts']=={'aminer':10,'wazuh':20} for w in supplement['windows'])
    assert all((discovery.datetime.fromisoformat(w['window_end'].replace('Z','+00:00'))-
                discovery.datetime.fromisoformat(w['window_start'].replace('Z','+00:00'))).total_seconds()==900
               for w in supplement['windows'])
    assert plan['windows'][0]['window_start'] not in [w['window_start'] for w in supplement['windows']]


def test_completed_search_plan_cannot_be_silently_overwritten(tmp_path,monkeypatch):
    (tmp_path/'search_plan.json').write_text('{}',encoding='utf8')
    monkeypatch.setattr(discovery,'OUT',tmp_path)
    with pytest.raises(ValueError,match='already_exists'):
        discovery.index()


def test_final_failure_report_requires_completed_search(tmp_path,monkeypatch):
    discovery.atomic_json(tmp_path/'search_plan.json',{'windows':[{'scene':'synthetic','window_start':'synthetic'}]})
    discovery.atomic_json(tmp_path/'candidate_results.json',[])
    monkeypatch.setattr(discovery,'OUT',tmp_path)
    with pytest.raises(ValueError,match='search_not_complete'):
        discovery.report_not_found()
    assert not (tmp_path/'FINAL_DEMO_REPORT.md').exists()


def test_failure_branch_cannot_publish_a_qualifying_positive(tmp_path,monkeypatch):
    w = {'scene':'synthetic','window_start':'synthetic','raw_counts':{'wazuh':3}}
    discovery.atomic_json(tmp_path/'search_plan.json',{'windows':[w]})
    discovery.atomic_json(tmp_path/'candidate_results.json',[{**w,'raw_alert_count':3,'is_complete':True,
        'correlation_edge_count':1,'multi_alert_incident_count':1,'singleton_incident_count':1}])
    monkeypatch.setattr(discovery,'OUT',tmp_path)
    with pytest.raises(ValueError,match='require_dataset_and_runtime'):
        discovery.report_not_found()
    assert not (tmp_path/'FINAL_DEMO_REPORT.md').exists()
