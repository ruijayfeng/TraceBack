"""Seal ordering and production isolation do not depend on favorable scores."""
import ast
from pathlib import Path
import pytest
from evaluation.framework.semantic_repair import evaluate, runtime, ROOT


def test_evaluation_rejects_before_any_truth_read(monkeypatch):
    reads = []
    def blocked(stage): raise ValueError('unsealed')
    monkeypatch.setattr(evaluate, 'verify_seal', blocked)
    monkeypatch.setattr(evaluate, 'read', lambda p: reads.append(p))
    with pytest.raises(ValueError, match='unsealed'): evaluate.run('final')
    assert reads == []


def test_production_candidate_has_no_truth_imports_or_dataset_constants():
    for path in (ROOT/'backend/app/correlation/semantic_repair').glob('*.py'):
        source = path.read_text(encoding='utf8')
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.ImportFrom): assert not (node.module or '').startswith('evaluation')
            if isinstance(node, ast.Import): assert all(not x.name.startswith('evaluation') for x in node.names)
        for token in ('GT-E0', 't5-prod-', 'svc_backup', '10.0.1.5', 'CPTC', 'labels.csv'):
            assert token not in source


def test_full_blind_replay_guard_and_all_three_seals():
    source = (ROOT/'evaluation/framework/semantic_repair/runtime.py').read_text(encoding='utf8')
    assert source.index('with guard(allowed, destination)') < source.index('variants = {design: aggregate')
    assert "score_sealed=True, direction_sealed=True, graph_sealed=True" in source
    assert "count != frozen['member_count']" in source
    assert "OLD/'blind/pair_scores.jsonl.gz'" in source
    blind = source[source.index('def blind(stage):'):]
    assert 'label_projection' not in blind and 'ground_truth_edge_scores' not in blind


def test_unknown_selection_and_immutable_freeze_guard(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, 'OUT', tmp_path)
    # Even an absent final seal cannot trigger truth loading or fallback scoring.
    with pytest.raises(FileNotFoundError): runtime.verify_seal('final')
