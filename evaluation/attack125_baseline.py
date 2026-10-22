"""LEGACY experiment coordinator; not the official Stage 1–4 analysis entry.

Integrity hashing, isolated historical runtime, then evaluation.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DATA = Path('D:/Code_WorkSpace/TraceBack-Dataset/data/attack125')
INPUT = DATA / 'final/attack125_final.jsonl'
TRUTH = DATA / 'ground_truth/ground_truth.json'
MANIFEST = DATA / 'manifests/release_manifest.json'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, data):
    Path(path).write_text(json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2) + '\n', encoding='utf8')


def protected_hashes():
    return {str(p): sha(p) for p in (INPUT, TRUTH, MANIFEST)}


def implementation_hashes():
    return {p.relative_to(ROOT).as_posix(): sha(p) for folder in ('backend/app', 'configs')
            for p in sorted((ROOT / folder).rglob('*'))
            if p.is_file() and '__pycache__' not in p.parts}


def predict(output):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    before = dict(protected_files=protected_hashes(), implementation=implementation_hashes(),
                  time=datetime.now(timezone.utc).isoformat(),
                  note='GT and release manifest are hashed as opaque bytes only; never parsed or passed to runtime.')
    save(output / 'before_hashes.json', before)
    env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONHASHSEED': '0'}
    with (output / 'runtime.log').open('w', encoding='utf8') as log:
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'evaluation/attack125_runtime.py'),
            '--input', str(INPUT), '--output', str(output / 'runtime')], env=env, cwd=ROOT,
            stdout=log, stderr=subprocess.STDOUT)
    after = dict(protected_files=protected_hashes(), implementation=implementation_hashes(),
                 runtime_returncode=result.returncode, time=datetime.now(timezone.utc).isoformat())
    save(output / 'after_runtime_hashes.json', after)
    assert before['protected_files'] == after['protected_files'], 'frozen_input_changed'
    assert before['implementation'] == after['implementation'], 'production_implementation_changed'
    if result.returncode:
        raise RuntimeError('runtime_failed; inspect runtime.log; no evaluation allowed')
    receipt = json.loads((output / 'runtime/runtime_manifest.json').read_text(encoding='utf8'))
    if not receipt['RUNTIME_COMPLETE']:
        print('ATTACK125_ADAPTER_INTEGRATION_BLOCKED')
        return
    seal = dict(runtime_manifest_sha256=sha(output / 'runtime/runtime_manifest.json'),
                artifacts=receipt['artifacts'], sealed_at=datetime.now(timezone.utc).isoformat(),
                ground_truth_semantically_loaded=False)
    save(output / 'prediction_seal.json', seal)
    print(json.dumps(receipt['summary'], indent=2))


def verify_seal(output):
    output = Path(output)
    seal = json.loads((output / 'prediction_seal.json').read_text(encoding='utf8'))
    assert sha(output / 'runtime/runtime_manifest.json') == seal['runtime_manifest_sha256']
    for name, expected in seal['artifacts'].items():
        assert sha(output / 'runtime' / name) == expected, 'prediction_changed:' + name
    before = json.loads((output / 'before_hashes.json').read_text(encoding='utf8'))
    assert protected_hashes() == before['protected_files']
    assert implementation_hashes() == before['implementation']
    return seal


def validate(output):
    """Finalize evidence checks without any algorithm or semantic GT replay."""
    from collections import Counter
    import xml.etree.ElementTree as ET
    output = Path(output).resolve()
    verify_seal(output)
    tests = []
    for name in ('experiment_tests', 'production_tests', 'stable_id_tests', 'schema_config_tests'):
        suite = ET.parse(output / (name + '.xml')).getroot().find('testsuite')
        counts = {k: int(suite.attrib[k]) for k in ('tests', 'failures', 'errors', 'skipped')}
        assert counts['failures'] == counts['errors'] == 0
        tests.append(dict(name=name, **counts, passed=counts['tests'] - counts['skipped'],
                          skipped_reasons=[e.attrib.get('message') for e in suite.iter('skipped')]))
    def read(name):
        return json.loads((output / 'runtime' / name).read_text(encoding='utf8'))
    alerts = {a['alert_id']: a for a in read('canonical_alerts.json')}
    incidents, nodes, edges = (read(n) for n in ('predicted_incidents.json', 'predicted_stages.json', 'predicted_edges.json'))
    for records in (incidents, nodes):
        counts = Counter(a for r in records for a in r['alert_ids'])
        assert set(counts) == set(alerts) and set(counts.values()) == {1}
    node_map = {n['predicted_stage_id']: n for n in nodes}
    for edge in edges:
        left, right = node_map[edge['src_stage']], node_map[edge['dst_stage']]
        assert left['incident_id'] == right['incident_id'] == edge['incident_id']
        assert set(edge['alert_ids']) <= set(left['alert_ids']) | set(right['alert_ids'])
        assert set(edge['alert_ids']) & set(left['alert_ids']) and set(edge['alert_ids']) & set(right['alert_ids'])
        assert edge['primary_evidence'] and edge['score_breakdown']
    required = ['predicted_communities.json', 'predicted_incidents.json', 'predicted_stages.json',
                'predicted_edges.json', 'predicted_attack_chains.json']
    replay_comparisons = {}
    # These were executed before the first semantic truth read. Their final
    # guard/seal failures do not make them additional official baselines.
    for attempt in ('run01', 'run02', 'run03'):
        previous = output.parent / ('attack125_baseline_20261019_' + attempt) / 'runtime'
        if all((previous / n).is_file() for n in required):
            replay_comparisons[attempt] = {n: sha(previous / n) == sha(output / 'runtime' / n) for n in required}
            assert all(replay_comparisons[attempt].values()), 'predictions_not_reproducible'
    before = json.loads((output / 'before_hashes.json').read_text(encoding='utf8'))
    receipt = dict(prediction_seal_verified=True, protected_files_unchanged=True,
        production_and_config_files_unchanged=True, protected_file_sha256=protected_hashes(),
        protected_implementation_file_count=len(before['implementation']),
        tests=tests, completed_tests_passed=sum(t['passed'] for t in tests),
        completed_tests_skipped=sum(t['skipped'] for t in tests),
        alert_incident_and_node_membership_partition_valid=True,
        all_edge_endpoint_and_evidence_references_valid=True,
        pre_gt_attempt_prediction_byte_equality=replay_comparisons,
        extra_test_attempt='Initial combined suite including test_api_isolation was interrupted without a final result; excluded from completed-test counts. No API acceptance claimed.',
        new_source_files=['evaluation/attack125_baseline.py', 'evaluation/attack125_runtime.py',
                          'evaluation/attack125_evaluate.py', 'evaluation/tests/test_attack125_baseline.py'])
    save(output / 'validation.json', receipt)
    report = output / 'REPORT.md'
    content = report.read_text(encoding='utf8')
    marker = '\n## 最终验证记录\n'
    content = content.split(marker)[0]
    content += marker + '\n'
    content += f"已完成测试：{receipt['completed_tests_passed']} passed、{receipt['completed_tests_skipped']} skipped；无失败。详见 validation.json 和四份 JUnit XML。\n\n"
    content += '首次额外组合测试含 API isolation，未完成并中断；不计入通过数，不宣称 API 验收。\n\n'
    content += '五份预测 JSON 在 GT 加载前的四次执行中逐字节一致；run01–03 因实验运行器最终白名单/封存检查失败，仅作诊断保留。run04 为唯一正式 baseline。\n\n'
    content += '三个冻结文件 SHA-256：\n\n'
    for path, digest in receipt['protected_file_sha256'].items():
        content += f'- `{Path(path).name}`：`{digest}`\n'
    content += '\n复现时使用新目录，既有目录拒绝覆盖：\n\n```powershell\n'
    content += '.\\.venv\\Scripts\\python.exe -B evaluation\\attack125_baseline.py predict --output evaluation\\outputs\\attack125_baseline_NEW\n'
    content += '.\\.venv\\Scripts\\python.exe -B evaluation\\attack125_baseline.py evaluate --output evaluation\\outputs\\attack125_baseline_NEW\n```\n'
    report.write_text(content, encoding='utf8')
    print(json.dumps({k: receipt[k] for k in ('prediction_seal_verified', 'completed_tests_passed', 'completed_tests_skipped',
        'protected_implementation_file_count', 'protected_files_unchanged', 'production_and_config_files_unchanged')}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['predict', 'evaluate', 'verify'])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.action == 'predict':
        predict(args.output)
    elif args.action == 'evaluate':
        verify_seal(args.output)
        from attack125_evaluate import evaluate
        evaluate(args.output, TRUTH)
    else:
        validate(args.output)
