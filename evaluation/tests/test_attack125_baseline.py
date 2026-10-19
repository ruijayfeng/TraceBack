"""Meaningful controls for the experiment, independent of ATTACK125 answers."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('attack125_runtime', ROOT / 'evaluation/attack125_runtime.py')
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)
sys.path.insert(0, str(ROOT / 'evaluation'))
from attack125_evaluate import stage_alignment, connected_aligned_path, binding_diagnosis


def test_longest_path_uses_edges_instead_of_timestamp_or_input_order():
    assert runtime.longest_path(['d', 'c', 'b', 'a'], [('a', 'c'), ('c', 'd'), ('a', 'b')]) == ['a', 'c', 'd']
    assert runtime.longest_path(['b', 'a'], []) == ['a']
    assert runtime.longest_path([], []) == []
    with pytest.raises(ValueError, match='not_dag'):
        runtime.longest_path(['a', 'b'], [('a', 'b'), ('b', 'a')])


def test_guard_blocks_truth_alternate_dataset_write_and_evaluation_import(tmp_path):
    source = tmp_path / 'native.jsonl'
    source.write_text('{}\n')
    truth = tmp_path / 'ground_truth.json'
    truth.write_text('{"answer": 1}')
    output = tmp_path / 'out'
    output.mkdir()
    program = '''
import importlib.util, json, pathlib, sys
s=importlib.util.spec_from_file_location('runtime',sys.argv[1])
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
source,truth,out=map(pathlib.Path,sys.argv[2:])
reads,denied=m.install_guard(source.resolve(),out.resolve())
assert source.read_text()=='{}\\n'
for action in [lambda:truth.read_text(),lambda:truth.write_text('changed'),lambda:__import__('evaluation')]:
    try:action()
    except PermissionError:pass
    else:raise AssertionError('tripwire did not block')
assert len(denied)==3
assert str(truth.resolve()) not in reads
print('blocked=3')
'''
    result = subprocess.run([sys.executable, '-B', '-c', program,
        str(ROOT / 'evaluation/attack125_runtime.py'), str(source), str(truth), str(output)],
        capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'blocked=3'
    assert json.loads(truth.read_text()) == {'answer': 1}


def test_alignment_is_one_to_one_and_reordering_stable():
    predictions = [dict(predicted_stage_id='p2', alert_ids=['a', 'b']),
                   dict(predicted_stage_id='p1', alert_ids=['a'])]
    truth = {'g2': {'b'}, 'g1': {'a'}}
    assert stage_alignment(predictions, truth) == {'g1': 'p1', 'g2': 'p2'}
    assert stage_alignment(list(reversed(predictions)), dict(reversed(list(truth.items())))) == stage_alignment(predictions, truth)
    assert len(stage_alignment(predictions[:1], truth)) == 1
    assert stage_alignment(predictions, {'other': {'unrelated'}}) == {}


def test_disconnected_stage_fragments_cannot_fake_a_contiguous_chain():
    nodes = ['a', 'b1', 'b2', 'c']
    owners = {'a': 's1', 'b1': 's2', 'b2': 's2', 'c': 's3'}
    order = {'s1': 0, 's2': 1, 's3': 2}
    edges = [dict(src_stage='a', dst_stage='b1'), dict(src_stage='b2', dst_stage='c')]
    assert connected_aligned_path(nodes, edges, owners, order)['edge_count'] == 1
    edges.append(dict(src_stage='b1', dst_stage='b2'))
    result = connected_aligned_path(nodes, edges, owners, order)
    assert result['edge_count'] == 2
    assert result['node_path'] == ['a', 'b1', 'b2', 'c']
    assert result['gt_stage_path'] == ['s1', 's2', 's3']


def test_equal_short_binding_value_with_different_scope_is_not_identity():
    left = dict(entity_occurrences=[], contexts=[dict(kind='flow', value='42', scope='sensor-a', raw_pointer='/connection_id')])
    right = dict(entity_occurrences=[], contexts=[dict(kind='flow', value='42', scope='sensor-b', raw_pointer='/connection_id')])
    bindings = [dict(source_field='event.connection_id', target_field='event.connection_id', value='42', binding_type='flow')]
    result = binding_diagnosis(left, right, bindings)
    assert result['earliest_identity_layer'] == 'BINDING_EXTRACTION_FAILURE'
    assert result['binding_comparisons'][0]['equal_context_value']
    assert not result['binding_comparisons'][0]['equal_context_key']
