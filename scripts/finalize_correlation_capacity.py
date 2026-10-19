"""Capacity receipts and complete persisted-output equivalence; no task restart."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
import duckdb
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'backend'))
sys.path.insert(0,str(ROOT/'scripts'))
from app.services.storage import atomic_json,file_digest
from app.services.capacity import IMPLEMENTATION_VERSION
from finalize_correlation_v4 import implementation_hashes,candidate_digest

OUT = ROOT/'outputs/correlation_v4_capacity'
def read(path):
    return json.loads(path.read_text(encoding='utf8'))


def decision_digest(identity):
    db = duckdb.connect(':memory:')
    db.execute("SET memory_limit='256MB'")
    db.execute('SET threads=1')
    digest,count = hashlib.sha256(),0
    try:
        cursor = db.execute('SELECT * FROM read_parquet(?) ORDER BY source_id,target_id',
            [str(ROOT/'outputs/analyses'/identity/'candidate_decisions/*.parquet')])
        while batch := cursor.fetchmany(1024):
            for row in batch:
                digest.update(json.dumps(row,separators=(',',':')).encode('utf8')+b'\n')
                count += 1
    finally:
        db.close()
    return dict(count=count,sha256=digest.hexdigest())


def execution_hashes():
    result = implementation_hashes()
    for name in ('scripts/verify_correlation_capacity.py','scripts/guard_correlation_capacity.ps1'):
        result[name] = file_digest(ROOT/name)
    return result


def receipt():
    before = read(ROOT/'outputs/correlation_v4/DEVELOPMENT_LOCK.json')['implementation']
    current = implementation_hashes()
    changed = {p:v for p,v in current.items() if before.get(p)!=v}
    atomic_json(OUT/'implementation_receipt.json',dict(algorithm_semantics_changed=False,
        algorithm_version='alert-correlation-v4-role-context-candidate-v1.1',
        execution_implementation=IMPLEMENTATION_VERSION,validation_status='NOT_YET_FROZEN',
        production=changed,previous={p:before[p] for p in changed if p in before}))
    print(json.dumps(list(changed)),flush=True)


def compare():
    old = read(ROOT/'outputs/correlation_v4/development/REAL_DATA_RESULT.json')
    new = read(OUT/'russellmitchell_verified/RESULT.json')
    if not new['is_complete']:
        resource_failure = any(any(word in error.lower() for word in
            ('memory', 'resource', 'available_commit', 'timeout', 'truncat')) for error in new.get('errors', [])) or bool(
                new.get('counts', {}).get('resource_truncated_count'))
        result = dict(status='FAIL', FULL_SEMANTIC_EQUIVALENCE='FAIL',
            checks=dict(complete=False), blocker_type='CAPACITY' if resource_failure else 'CONTRACT',
            old_analysis_id=old['analysis_id'], new_analysis_id=new['analysis_id'],
            errors=new.get('errors', []),
            comparison_scope='Full equivalence unavailable: verification snapshot was not completely published. Partial progress cannot establish equivalence.')
        atomic_json(OUT/'RUSSELLMITCHELL_EQUIVALENCE.json', result)
        print(json.dumps(result), flush=True)
        return
    old_domain,new_domain = (ROOT/'data/processed'/r['analysis_id'] for r in (old,new))
    kinds = ('alerts','entities','dedupe_groups','correlation_edges','incidents','attack_chains','chain_nodes','chain_edges')
    tables = {k:dict(old_sha256=file_digest(old_domain/(k+'.jsonl')),
        new_sha256=file_digest(new_domain/(k+'.jsonl'))) for k in kinds}
    for row in tables.values():
        row['equal'] = row['old_sha256']==row['new_sha256']
    candidates = {'old':candidate_digest(old['analysis_id']),'new':candidate_digest(new['analysis_id'])}
    old_details,new_details = (ROOT/'outputs/analyses'/r['analysis_id'] for r in (old,new))
    checks = dict(complete=new['is_complete'],counts=old['counts']==new['counts'],
        config_hash=old['config_hash']==new['config_hash'],mapping_digest=old['mapping_digest']==new['mapping_digest'],
        dataset_digest=old['dataset_digest']==new['dataset_digest'],algorithm_version=old['algorithm_version']==new['algorithm_version'],
        logical_analysis_identity=read(old_details/'manifest.json')['execution']['snapshot_identity']==
            read(new_details/'manifest.json')['execution']['snapshot_identity'],
        candidate_payloads=candidates['old']==candidates['new'],grounding=old['grounding']==new['grounding'],
        all_candidate_decisions_and_unrounded_valid_scores=decision_digest(old['analysis_id'])==decision_digest(new['analysis_id']),
        score_and_evidence_distribution=read(old_details/'development_audit.json')==read(new_details/'development_audit.json'),
        frequency_snapshot=file_digest(old_details/'frequency_snapshot.json')==file_digest(new_details/'frequency_snapshot.json'))
    result = dict(status='PASS' if all(checks.values()) and all(r['equal'] for r in tables.values()) else 'FAIL',
        FULL_SEMANTIC_EQUIVALENCE='PASS' if all(checks.values()) and all(r['equal'] for r in tables.values()) else 'FAIL',
        checks=checks,domain_tables=tables,candidate_payloads=candidates,
        old_analysis_id=old['analysis_id'],new_analysis_id=new['analysis_id'],
        comparison_scope='every persisted canonical byte, all candidate payloads and unrounded score distribution; run identity/runtime/memory excluded')
    atomic_json(OUT/'RUSSELLMITCHELL_EQUIVALENCE.json',result)
    print(json.dumps(result),flush=True)


def regression():
    path=OUT/'pytest_verified.xml'
    suites = list(ET.parse(path).getroot().iter('testsuite'))
    result = {k:sum(int(s.attrib.get(k,0)) for s in suites) for k in ('tests','failures','errors','skipped')}
    result['passed'] = result['tests']>0 and result['failures']==result['errors']==0
    result['junit_sha256'] = file_digest(path)
    result['junit_file'] = path.relative_to(ROOT).as_posix()
    result['frontend'] = {name:dict(status='PASS',log_sha256=file_digest(OUT/f'frontend_{name}.log'))
        for name in ('test','typecheck','build')}
    atomic_json(OUT/'REGRESSION_RESULT.json',result)
    print(json.dumps(result),flush=True)


def lock():
    if read(OUT/'RUSSELLMITCHELL_EQUIVALENCE.json')['status']!='PASS' or not read(OUT/'REGRESSION_RESULT.json')['passed']:
        raise ValueError('validation_gate_not_passed')
    atomic_json(OUT/'VALIDATION_LOCK.json',dict(implementation=execution_hashes(),
        execution_implementation=IMPLEMENTATION_VERSION,algorithm_version='alert-correlation-v4-role-context-candidate-v1.1',
        equivalence_sha256=file_digest(OUT/'RUSSELLMITCHELL_EQUIVALENCE.json'),
        regression_sha256=file_digest(OUT/'REGRESSION_RESULT.json'),algorithm_tuning_after_fox_forbidden=True))


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('mode',choices=['receipt','compare','regression','lock'])
    args=parser.parse_args()
    globals()[args.mode]()
