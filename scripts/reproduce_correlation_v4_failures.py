"""Synthetic counterexamples for hypotheses mined from development evidence."""
from pathlib import Path
import json
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'backend'), str(ROOT/'backend/tests')]
from app.config import load_config
from app.services.storage import atomic_json
from test_correlation_score import alert
from test_correlation_v3 import score, network_event


def run(version):
    config = load_config(ROOT/f'configs/algorithm-{version}.yaml')
    report = {}
    aa = [alert('a', host='rare', account='rare', rule_id='open', alert_type='generic'),
          alert('b', host='rare', account='rare', rule_id='close', alert_type='generic')]
    pair, _ = score(aa, config)
    report['generic_type'] = dict(score=pair.score, valid=pair.valid,
        metadata_strength=pair.diagnostics['evidence_v2']['family_strengths']['behavior'])
    aa = [alert('a', src_ip='192.0.2.1', dst_ip='192.0.2.9'),
          alert('b', 1, src_ip='192.0.2.2', dst_ip='192.0.2.9')]
    pair, _ = score(aa, config)
    report['destination_role'] = pair.diagnostics['evidence_v2']['entity_reliability']
    aa = [network_event(alert('a', src_ip='192.0.2.1', dst_ip='192.0.2.2', src_port=1000, dst_port=80), 'f1'),
          network_event(alert('b', 1, src_ip='192.0.2.2', dst_ip='192.0.2.3', src_port=80, dst_port=1001), 'f2')]
    pair, _ = score(aa, config)
    ev = pair.diagnostics['evidence_v2']
    report['port_only_context'] = dict(score=pair.score, valid=pair.valid,
        network_valid=ev['network_continuity_valid'], diagnostic=ev['network_diagnostic'],
        primary=ev['primary_evidence'], hard_guard=pair.rejection_codes)
    report['synthetic'] = True
    report['ground_truth_used'] = False
    atomic_json(ROOT/'outputs/correlation_v4'/f'{version}_counterexamples.json', report)
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__': run(sys.argv[1])
