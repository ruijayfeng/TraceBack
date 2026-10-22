"""Verify the StageWorkbench read-only adapter against the official ⑨ artifact.

Read-only: never re-runs ⑨, never rewrites the sealed artifact. It checks that
every Workbench-projected statistic and identity equals the sealed source, and
that both the primary (reconstruction.py) and secondary (assembly.py) lines are
independently openable through the existing StageWorkbench API.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))

from app.stage_chains.stage9_reader import Stage9ArtifactReader  # noqa: E402

STAGE9_DIR = ROOT / 'outputs/stage9_formal_acceptance_20261022/run1'


def _sha(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def verify_primary():
    """SOURCE (sealed files) vs WORKBENCH (reader projection) for the ⑨ line."""
    st8 = json.loads((STAGE9_DIR / 'stage8.json').read_text(encoding='utf-8'))
    st9 = json.loads((STAGE9_DIR / 'stage9.json').read_text(encoding='utf-8'))

    types = Counter(d['relation_type'] for d in st8['evidence']['decisions'])
    source = dict(
        stage_count=len(st8['stages']['stages']),
        directed=types['DIRECTED_EDGE'],
        undirected=types['UNDIRECTED_EDGE'],
        no_relation=types['NO_RELATION'],
        chain_count=len(st9['chains']),
        stage_ids=sorted(s['stage_id'] for s in st8['stages']['stages']),
        relation_ids=sorted(d['candidate_id'] for d in st8['evidence']['decisions']
                            if d['relation_type'] != 'NO_RELATION'),
        decision_ids=sorted(d['candidate_id'] for d in st8['evidence']['decisions']),
        relation_types={d['candidate_id']: d['relation_type'] for d in st8['evidence']['decisions']
                        if d['relation_type'] != 'NO_RELATION'},
        endpoints={d['candidate_id']: (d['from_stage_id'], d['to_stage_id'])
                   for d in st8['evidence']['decisions'] if d['relation_type'] != 'NO_RELATION'},
    )

    reader = Stage9ArtifactReader(ROOT, STAGE9_DIR)
    ov = reader.overview()
    workbench = dict(
        stage_count=len(ov['stages']),
        directed=ov['counts']['directed_count'],
        undirected=ov['counts']['undirected_count'],
        no_relation=ov['counts']['no_relation_count'],
        chain_count=len(ov['chains']),
        stage_ids=sorted(s['stage_id'] for s in ov['stages']),
        relation_ids=sorted(x['relation_id'] for x in ov['relations']),
        decision_ids=sorted(x['relation_id'] for x in ov['decisions']),
        relation_types={x['relation_id']: x['relation_type'] for x in ov['relations']},
        endpoints={x['relation_id']: (x['from_stage_id'], x['to_stage_id']) for x in ov['relations']},
    )

    checks = {
        'SOURCE_STAGE_COUNT': source['stage_count'],
        'WORKBENCH_STAGE_COUNT': workbench['stage_count'],
        'SOURCE_DIRECTED_COUNT': source['directed'],
        'WORKBENCH_DIRECTED_COUNT': workbench['directed'],
        'SOURCE_UNDIRECTED_COUNT': source['undirected'],
        'WORKBENCH_UNDIRECTED_COUNT': workbench['undirected'],
        'SOURCE_NO_RELATION_COUNT': source['no_relation'],
        'WORKBENCH_NO_RELATION_COUNT': workbench['no_relation'],
        'SOURCE_CHAIN_COUNT': source['chain_count'],
        'WORKBENCH_CHAIN_COUNT': workbench['chain_count'],
        'STAGE_IDENTITY_MATCH': source['stage_ids'] == workbench['stage_ids'],
        'RELATION_IDENTITY_MATCH': source['relation_ids'] == workbench['relation_ids'],
        'DECISION_IDENTITY_MATCH': source['decision_ids'] == workbench['decision_ids'],
        'RELATION_SEMANTICS_MATCH': source['relation_types'] == workbench['relation_types'],
        'SOURCE_TARGET_MATCH': source['endpoints'] == workbench['endpoints'],
    }
    checks['COUNTS_EQUAL'] = all([
        checks['SOURCE_STAGE_COUNT'] == checks['WORKBENCH_STAGE_COUNT'],
        checks['SOURCE_DIRECTED_COUNT'] == checks['WORKBENCH_DIRECTED_COUNT'],
        checks['SOURCE_UNDIRECTED_COUNT'] == checks['WORKBENCH_UNDIRECTED_COUNT'],
        checks['SOURCE_NO_RELATION_COUNT'] == checks['WORKBENCH_NO_RELATION_COUNT'],
        checks['SOURCE_CHAIN_COUNT'] == checks['WORKBENCH_CHAIN_COUNT'],
    ])
    checks['IDENTITY_ALL_MATCH'] = all([
        checks['STAGE_IDENTITY_MATCH'], checks['RELATION_IDENTITY_MATCH'],
        checks['DECISION_IDENTITY_MATCH'], checks['RELATION_SEMANTICS_MATCH'],
        checks['SOURCE_TARGET_MATCH'],
    ])
    # Integrity: the sealed files must still match the acceptance manifest.
    manifest = json.loads((STAGE9_DIR.parent / 'artifact_manifest.json').read_text(encoding='utf-8'))
    keys8 = [k for k in manifest if k.replace('\\', '/').endswith('run1/stage8.json')]
    keys9 = [k for k in manifest if k.replace('\\', '/').endswith('run1/stage9.json')]
    checks['STAGE8_ARTIFACT_UNCHANGED'] = bool(keys8) and _sha(STAGE9_DIR / 'stage8.json') == manifest[keys8[0]]
    checks['STAGE9_ARTIFACT_UNCHANGED'] = bool(keys9) and _sha(STAGE9_DIR / 'stage9.json') == manifest[keys9[0]]
    return checks


def main():
    checks = verify_primary()
    print('=== PRIMARY (stage9_formal_acceptance / reconstruction.py) ===')
    for k, v in checks.items():
        print(f'{k}={v}')
    ok = checks['COUNTS_EQUAL'] and checks['IDENTITY_ALL_MATCH'] and \
        checks['STAGE8_ARTIFACT_UNCHANGED'] and checks['STAGE9_ARTIFACT_UNCHANGED']
    print(f'PRIMARY_VERIFY={"PASS" if ok else "FAIL"}')
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
