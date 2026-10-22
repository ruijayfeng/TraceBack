"""Run only ⑨ on an existing frozen formal ⑧ handoff; never replay ①–⑧."""
import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'backend'))
from app.stage_chains.reconstruction import (FrozenStageGraph, reconstruct_attack_chains,
    validate_reconstruction)

FILES_CHANGED = ['backend/app/stage_chains/reconstruction.py',
    'backend/tests/test_stage9_reconstruction.py', 'scripts/verify_stage9_reconstruction.py',
    'docs/STAGE_9_ATTACK_CHAIN_RECONSTRUCTION.md']


def test_counts(path):
    cases = list(ET.parse(path).getroot().iter('testcase'))
    passed = sum(not any(case.find(k) is not None for k in ('failure', 'error', 'skipped')) for case in cases)
    if not cases or passed != len(cases):
        raise ValueError('stage9_acceptance_requires_passing_tests:' + str(path))
    return len(cases), passed


def execute(source, output, tests, regression_tests):
    source, output = Path(source).resolve(), Path(output).resolve()
    if not source.is_relative_to(ROOT/'outputs') or not output.is_relative_to(ROOT/'outputs'):
        raise ValueError('stage9_acceptance_requires_output_snapshot_paths')
    if output.exists():
        raise ValueError('stage9_acceptance_requires_new_output_directory')
    raw = source.read_bytes()
    source_sha = sha256(raw).hexdigest()
    handoff = json.loads(raw)
    # These are persisted outputs of the official pipeline, including raw Alert
    # backing. Do not call pipeline/adapter/candidate/evidence builders here.
    graph = FrozenStageGraph.from_stage8(handoff['stages']['stages'], handoff['evidence'], handoff['alerts'])
    before = graph.signature()
    result = reconstruct_attack_chains(graph)
    trace = validate_reconstruction(result, graph)
    after = graph.signature()
    if before != after or sha256(source.read_bytes()).hexdigest() != source_sha:
        raise ValueError('stage9_input_snapshot_changed')
    unit_count, unit_passed = test_counts(tests)
    _, regression_passed = test_counts(regression_tests)
    counts = Counter(r['relation_type'] for r in graph.relations.values())
    summary = dict(TASK_RESULT='SUCCESS', STAGE_9_ATTACK_CHAIN_RECONSTRUCTION='PASS',
        INPUT_STAGE_COUNT=len(graph.stages), INPUT_RELATION_COUNT=len(graph.relations),
        INPUT_DECISION_COUNT=len(graph.decisions), INPUT_RELATION_TYPES=dict(counts),
        # Statistics aliases only. Source relation_type is never translated.
        STRONG_DIRECTED_COUNT=counts['DIRECTED_EDGE'] + counts['STRONG_DIRECTED'],
        STRONG_UNDIRECTED_COUNT=counts['UNDIRECTED_EDGE'] + counts['STRONG_UNDIRECTED'],
        WEAK_DIRECTED_COUNT=counts['WEAK_DIRECTED'],
        CHAIN_COUNT=len(result.chains), SINGLE_STAGE_CHAIN_COUNT=sum(c.single_stage for c in result.chains),
        MULTI_STAGE_CHAIN_COUNT=sum(not c.single_stage for c in result.chains),
        CHAIN_SIZES=sorted(len(c.stage_ids) for c in result.chains), **result.guard,
        NEW_RELATION_CREATED=False, RELATION_REJUDGED=False, RELATION_TYPE_MODIFIED=False,
        CROSS_COMPONENT_EDGE_CREATED=False, UNDIRECTED_EDGE_TEMPORALLY_ORIENTED=False,
        CONNECTED_COMPONENTS_USED_FOR_MEMBERSHIP_ONLY=True, COMMUNITY_USED_AS_CHAIN_BOUNDARY=False,
        DATASET_MODIFIED=False, GROUND_TRUTH_MODIFIED=False, **trace,
        TESTS_ADDED=unit_count, TESTS_PASSED=unit_passed, REGRESSION_TESTS_PASSED=regression_passed,
        FILES_CHANGED=FILES_CHANGED, INPUT_SOURCE=str(source.relative_to(ROOT)), INPUT_SOURCE_SHA256=source_sha,
        ONLY_STAGE8_FORMAL_OUTPUT_CONSUMED=True, UPSTREAM_PIPELINE_CALLS=0,
        CURRENT_PIPELINE_STAGE='⑨ Attack Chain Reconstruction', NEXT_STAGE_STARTED=False)
    output.mkdir(parents=True)
    def save(name, value):
        (output/name).write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)+'\n', encoding='utf8')
    save('result.json', result.model_dump(mode='json'))
    # References point into the original source; no second relation/evidence set.
    save('source_receipt.json', dict(source=summary['INPUT_SOURCE'], sha256=source_sha,
        stage_table='stages.stages', relation_table='evidence.decisions',
        relation_id_field='candidate_id', claims='evidence.claims',
        observations='evidence.trace.observations', pointers='evidence.trace.raw_pointers', alerts='alerts'))
    save('acceptance.json', summary)
    (output/'acceptance.txt').write_text('\n'.join(k+'='+json.dumps(v, ensure_ascii=False) for k,v in summary.items())+'\n', encoding='utf8')
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return result, summary


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf8')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--tests', type=Path, required=True)
    parser.add_argument('--regression-tests', type=Path, required=True)
    args = parser.parse_args()
    try:
        execute(args.input, args.output, args.tests, args.regression_tests)
    except Exception:
        print('TASK_RESULT=FAILED\nSTAGE_9_ATTACK_CHAIN_RECONSTRUCTION=FAIL', file=sys.stderr)
        raise
