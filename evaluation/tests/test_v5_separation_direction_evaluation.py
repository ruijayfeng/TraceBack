"""Evaluation integrity and code-boundary witnesses, independent of outcomes."""
import ast
import pytest
from evaluation.framework.separation_direction import evaluate,ROOT


def test_evaluation_requires_verified_seal_before_any_GT_read(monkeypatch):
    reads=[]
    def blocked():raise ValueError('unsealed')
    monkeypatch.setattr(evaluate,'verify_seal',blocked)
    monkeypatch.setattr(evaluate,'read',lambda p:reads.append(p))
    with pytest.raises(ValueError,match='unsealed'):evaluate.run()
    assert reads==[]


def test_candidate_production_modules_do_not_import_evaluation():
    for p in (ROOT/'backend/app/correlation/separation_direction').glob('*.py'):
        tree=ast.parse(p.read_text(encoding='utf8'))
        for n in ast.walk(tree):
            if isinstance(n,ast.ImportFrom):assert not (n.module or '').startswith('evaluation')
            if isinstance(n,ast.Import):assert all(not a.name.startswith('evaluation') for a in n.names)
        assert 'GT-E' not in p.read_text(encoding='utf8')


def test_blind_guard_is_allowlisted_and_precedes_scoring():
    source=(ROOT/'evaluation/framework/separation_direction/runtime.py').read_text(encoding='utf8')
    assert source.index('with guard(allowed,destination)')<source.index('result=aggregate(')
    assert "'PairScore','DirectionEvidence','CorrelationEdge','ChainEdge'" in source
    assert 'evaluation/label_projection' not in source
    assert "'expected_member_count'" in source
