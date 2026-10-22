"""Official CLI integration and ⑧→⑨ boundary regressions."""
import importlib.util
import json
from pathlib import Path

import pytest

from test_community_builder import record

ROOT = Path(__file__).resolve().parents[2]


def cli():
    spec = importlib.util.spec_from_file_location('stage9_cli', ROOT/'scripts/run_stage_pipeline.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def native(tmp_path):
    path = tmp_path/'native.jsonl'
    path.write_text(''.join(json.dumps(dict(source_type='edr', event=record(
        i, time=i, hostname='h', request_id='r', operation='ProcessStart')))+'\n'
        for i in range(3)), encoding='utf8')
    return path


def test_existing_official_cli_executes_stage9(tmp_path, capsys):
    run = cli().execute(native(tmp_path))
    assert run.statistics['STAGE_9_STARTED'] is True
    assert run.statistics['CURRENT_PIPELINE_STAGE'] == '⑨ Attack Chain Reconstruction'
    assert sorted(s for c in run.reconstruction.chains for s in c.stage_ids) == sorted(run.graph.stages)
    assert sorted(r for c in run.reconstruction.chains for r in c.relation_ids) == sorted(run.graph.relations)


def test_official_cli_publishes_source_and_refuses_overwrite(tmp_path, capsys):
    path = native(tmp_path)
    output = tmp_path/'run'
    run = cli().execute(path, output=output)
    stage8 = json.loads((output/'stage8.json').read_text(encoding='utf8'))
    stage9 = json.loads((output/'stage9.json').read_text(encoding='utf8'))
    assert stage8['evidence'] == run.upstream.evidence_result.model_dump(mode='json')
    assert stage9 == run.reconstruction.model_dump(mode='json')
    before = {p.name: p.read_bytes() for p in output.iterdir()}
    with pytest.raises(FileExistsError):
        cli().execute(path, output=output)
    assert {p.name: p.read_bytes() for p in output.iterdir()} == before


def test_handoff_consumes_same_upstream_objects_once(tmp_path, monkeypatch):
    from app.stage_chains import pipeline
    from app.stage_chains.reconstruction import FrozenStageGraph
    calls = []
    original = pipeline.load_stage_pipeline
    def upstream(*args, **kwargs):
        calls.append('upstream')
        return original(*args, **kwargs)
    consume = FrozenStageGraph.from_stage8
    def boundary(stages, evidence, alerts):
        calls.append((stages, evidence, alerts))
        return consume(stages, evidence, alerts)
    monkeypatch.setattr(pipeline, 'load_stage_pipeline', upstream)
    monkeypatch.setattr(FrozenStageGraph, 'from_stage8', boundary)
    run = pipeline.load_attack_chain_pipeline(native(tmp_path))
    assert len(calls) == 2 and calls[0] == 'upstream'
    assert calls[1][0] is run.upstream.stages.stages
    assert calls[1][1] is run.upstream.evidence_result
    assert calls[1][2] is run.upstream.community.alerts


def test_multi_entry_exit_and_undirected_only_nodes():
    from app.stage_chains.reconstruction import arrow_metadata
    arrows = [dict(relation_type='DIRECTED_EDGE', from_stage_id=a, to_stage_id=b)
              for a, b in [('a', 'c'), ('b', 'c'), ('c', 'd'), ('c', 'e')]]
    arrows.append(dict(relation_type='UNDIRECTED_EDGE', from_stage_id=None, to_stage_id=None))
    assert arrow_metadata(list('abcdef'), arrows) == (['a', 'b'], ['d', 'e'], False)


def test_duplicate_stage8_decision_is_rejected(tmp_path):
    from app.services.stage_pipeline import load_stage_pipeline
    from app.stage_chains.reconstruction import FrozenStageGraph
    # Native alerts yielding multiple stages and an actual ⑧ decision.
    path = tmp_path/'pair.jsonl'
    rows = [record(1, hostname='h', session_id='s'), record(2, hostname='h', session_id='s', time=300)]
    path.write_text(''.join(json.dumps(dict(source_type='edr', event=r))+'\n' for r in rows), encoding='utf8')
    run = load_stage_pipeline(path)
    assert run.evidence_result.decisions
    evidence = run.evidence_result.model_dump(mode='json')
    evidence['decisions'].append(evidence['decisions'][0])
    with pytest.raises(ValueError, match='duplicate_or_missing_stage9_relation_id'):
        FrozenStageGraph.from_stage8(run.stages.stages, evidence, run.community.alerts)
