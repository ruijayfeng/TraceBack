"""Production can complete with GT missing, trapped, or moved away."""

import ast
import builtins
import json
from pathlib import Path

from test_analysis_service import service, write_input, request_for, edge_records, tripwire


def test_production_static_has_no_evaluation_or_truth_dependency():
    root = Path(__file__).resolve().parents[1]/"app"
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            imports = [a.name for a in node.names] if isinstance(node,ast.Import) else [node.module] if isinstance(node,ast.ImportFrom) and node.module else []
            assert all(name.split(".")[0] != "evaluation" for name in imports), str(path)
            if isinstance(node,ast.Constant) and isinstance(node.value,str):
                text = node.value.lower()
                assert not text.endswith("labels.csv") and not text.endswith("attacks.log") and not text.endswith("gold_chain.json"), str(path)


def test_production_with_gt_moved_and_runtime_read_import_tripwire(tmp_path,monkeypatch):
    svc = service(tmp_path,edge=True)
    input_path = write_input(tmp_path,edge_records())
    ground_truth = tmp_path/"data/ait_ads/synthetic/evaluation/labels.csv"
    ground_truth.parent.mkdir(parents=True)
    ground_truth.write_text("scenario,attack,start,end\nsynthetic,a,1,2\n")
    first = svc.create(request_for(input_path),background=False)
    from app.services.queries import QueryService
    assert QueryService(tmp_path).analysis(first)["status"] == "completed"
    ground_truth.rename(ground_truth.with_suffix(".unavailable"))
    reads = tripwire(monkeypatch)
    original_import = builtins.__import__
    def guarded_import(name,*args,**kwargs):
        assert name.split(".")[0] != "evaluation"
        return original_import(name,*args,**kwargs)
    monkeypatch.setattr(builtins,"__import__",guarded_import)
    second = svc.create(request_for(input_path),background=False)
    from app.services.queries import QueryService
    from app.services.storage import SnapshotStore
    assert QueryService(tmp_path).analysis(second)["status"] == "completed"
    assert list(SnapshotStore(tmp_path,first).read_records("correlation_edges")) == list(SnapshotStore(tmp_path,second).read_records("correlation_edges"))
    assert reads
