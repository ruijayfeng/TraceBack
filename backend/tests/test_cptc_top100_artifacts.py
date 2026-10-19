from evaluation.framework.preformula_baseline.boundary import development_config, development_cptc, verify_historical_inventory, verify_current
"""Read-only delivery checks; run after the real diagnostic artifacts exist."""
import json
from pathlib import Path
import sys

import pytest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from cptc_top100_diagnostic import OUT,read_json,protected_hashes
from app.models import CanonicalAlert,ScoreBreakdown
from app.models.base import resolve_pointer
from app.adapters.cptc import unwrap_splunk
from app.services.storage import file_digest


@pytest.fixture(scope='module')
def delivery():
    path=OUT/'CPTC_TOP100_MANIFEST.json'
    if not path.is_file():
        pytest.skip('Real CPTC diagnostic has not been generated')
    return read_json(path)


@pytest.mark.parametrize('name',['CPTC_TOP100_PAIRS.jsonl','CPTC_TOP100_ALL_MEMBERS_PAIRS.jsonl',
                               'CPTC_TOP100_CANDIDATE_AGGREGATES_PAIRS.jsonl'])
def test_all_100_real_pair_payloads_and_grounding(delivery,name):
    ranks=[];keys=[]
    with (OUT/name).open(encoding='utf8') as handle:
        for line in handle:
            row=json.loads(line)
            ranks.append(row['rank'])
            keys.append((-row['final_score'],row['ranking_alert_a_id'],row['ranking_alert_b_id']))
            alerts={}
            for side in ('A','B'):
                alert=CanonicalAlert.model_validate(row['canonical_alerts'][side])
                assert alert.alert_id==row['alert_'+side.lower()+'_id']
                assert row['raw_alerts'][side]['alert_id']==alert.alert_id
                assert row['raw_alerts'][side]['raw_fingerprint']==alert.raw_fingerprint
                assert row['raw_alerts'][side]['records']
                for record in row['raw_alerts'][side]['records']:
                    assert unwrap_splunk(record['outer_record'])==record['parsed_suricata_eve']==alert.raw_alert
                for entity in row['entity_extraction'][side]:
                    assert resolve_pointer(alert.raw_alert,entity['evidence_pointer']['pointer'])==entity['raw_value']
                    assert entity['role'] and entity['entity_id'] in alert.entity_ids
                alerts[alert.alert_id]=alert
            for ref in row['evidence_independence']['raw_evidence_pointers']:
                assert ref['alert_id'] in alerts
                assert resolve_pointer(alerts[ref['alert_id']].raw_alert,ref['pointer'])==ref['resolved_value']
            scoring=row['scoring']
            assert scoring['status']=='PASS'
            assert abs(scoring['reconstructed_score']-row['final_score'])<=scoring['tolerance']
            frozen_dims={d['dimension'] for d in row['production_diagnostic']['evidence_v2']['dimensions']}
            assert {f['feature_name'] for f in scoring['features']}==frozen_dims|{'penalty.conflict','penalty.duplicate'}
            assert row['threshold_gap']==row['final_score']-row['formal_threshold']
            assert not row['formal_edge_admitted']
            ScoreBreakdown.model_validate(row['production_score_breakdown'])
    assert ranks==list(range(1,101))
    assert keys==sorted(keys)


def test_delivery_recipe_counts_and_original_inputs_unchanged(delivery):
    assert delivery['task_result']=='CPTC_TOP100_DIAGNOSTIC_COMPLETE'
    assert delivery['total_scored_pairs']==1708390
    assert delivery['total_scored_representative_candidates']==1551265
    assert delivery['total_scored_member_pairs']==1708390
    assert delivery['threshold']==.65
    assert not delivery['algorithm_modified'] and not delivery['config_modified'] and not delivery['raw_data_modified']
    assert verify_historical_inventory(read_json(OUT/'protected_before.json'), anchor=OUT/'protected_before.json')['status'] == 'PASS'
    for name,digest in delivery['files'].items():
        assert file_digest(OUT/name)==digest, name
    distribution=read_json(OUT/'CPTC_TOP100_SCORE_DISTRIBUTION.json')
    assert distribution['total_scored_pairs']==delivery['total_scored_pairs']
    assert distribution['representative_candidate_scores']['total_scored_pairs']==delivery['total_scored_representative_candidates']
