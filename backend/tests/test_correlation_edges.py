"""Integrated edges, complete member scoring, determinism and isolation."""

from itertools import combinations
import math
from pathlib import Path
import os

import pytest

from app.correlation.edges import run_correlation
from app.correlation.scoring import CorrelationScorer
from test_correlation_score import alert, config, configured, group, inputs, parent_child


def run(index,settings,config,**kwargs):
    return run_correlation(list(index.alerts.values()),kwargs.pop("groups",[]),list(index.entities.values()),config,settings,**kwargs)


def test_accepted_parent_child_mapping_and_unordered_endpoints(tmp_path):
    config=configured(tmp_path,entity={"rarity_enabled":False})
    index,settings=inputs(parent_child())
    first=run(index,settings,config)
    assert len(first.edges)==1 and first.record.is_complete
    edge=first.edges[0]
    assert edge.source_alert_id<edge.target_alert_id
    assert first.summary["relation_type_distribution"]=={"PROCESS_CAUSAL":1}
    assert edge.support_pair.alert_ids()==set(index.alerts)
    assert edge.score>=config.algorithm.score.correlation_threshold
    second=run_correlation(list(reversed(list(index.alerts.values()))),[],list(reversed(list(index.entities.values()))),config,settings)
    assert [e.canonical_json() for e in first.edges]==[e.canonical_json() for e in second.edges]
    assert first.record.analysis_id==second.record.analysis_id


def test_threshold_compared_unrounded_not_serialized(tmp_path):
    baseline=configured(tmp_path,entity={"rarity_enabled":False})
    index,settings=inputs(parent_child())
    raw=CorrelationScorer(index,baseline,settings).score_pair(*index.alerts).score
    equal=configured(tmp_path,entity={"rarity_enabled":False},score={"correlation_threshold":raw},clustering={"edge_threshold":1.0},chain={"edge_threshold":1.0})
    assert len(run(index,settings,equal).edges)==1
    above=configured(tmp_path,entity={"rarity_enabled":False},score={"correlation_threshold":math.nextafter(raw,math.inf)},clustering={"edge_threshold":1.0},chain={"edge_threshold":1.0})
    assert run(index,settings,above).edges==[]


def test_zero_degree_preserved_time_only_rejected(config):
    index,settings=inputs([alert("a"),alert("b",1),alert("isolated",9000)])
    result=run(index,settings,config)
    assert result.edges==[] and result.summary["zero_degree_alert_count"]==3
    assert set(result.record.input_alert_ids)==set(index.alerts)


def test_no_transitive_closure_or_duplicate_support_key(tmp_path):
    from app.adapters.base import AdapterSettings
    config=configured(tmp_path,entity={"rarity_enabled":False},score={"correlation_threshold":.3})
    values=[alert("a",host="ab",session="ab"),alert("b",1,host="ab",session="bc"),alert("c",2,host="bc",session="bc")]
    index,settings=inputs(values,{"synthetic":AdapterSettings("synthetic","synthetic","synthetic",session_scope="app")})
    result=run(index,settings,config)
    pairs={(e.source_alert_id,e.target_alert_id) for e in result.edges}
    assert tuple(sorted((values[0].alert_id,values[1].alert_id))) in pairs
    assert tuple(sorted((values[1].alert_id,values[2].alert_id))) in pairs
    assert tuple(sorted((values[0].alert_id,values[2].alert_id))) not in pairs
    assert len(pairs)==len(result.edges)


def test_all_members_verified_choose_real_winner_no_feature_splicing(tmp_path):
    config=configured(tmp_path,entity={"rarity_enabled":False},score={"correlation_threshold":.3})
    left=[alert("g1-a",5000,host="unused"),alert("g1-b",host="h",account="u")]
    right=[alert("g2-a",1,host="h",account="u"),alert("g2-b",5001,host="other")]
    g1,g2=group(left),group(right)
    index,settings=inputs(left+right,groups=[g1,g2])
    diagnostics=[]
    result=run(index,settings,config,groups=[g1,g2],diagnostic_sink=diagnostics.append)
    assert result.summary["verified_member_pair_count"]==4
    assert len([d for d in diagnostics if d["stage"]=="member_score"])==4
    assert len(result.edges)==1
    edge=result.edges[0]
    assert edge.support_pair.alert_ids()=={left[1].alert_id,right[0].alert_id}
    assert all(set(r.alert_ids)==edge.support_pair.alert_ids() for r in edge.reasons)
    scorer=CorrelationScorer(index,config,settings)
    expected=scorer.score_pair(edge.support_pair.alert_id_src,edge.support_pair.alert_id_dst)
    assert edge.score==round(expected.score,6)


def test_gt_read_tripwire_full_pipeline_and_incomplete_budget(tmp_path,monkeypatch):
    config=configured(tmp_path,candidate={"per_channel_neighbors":1,"time_only_neighbors":1,"max_neighbors_per_alert":1,"max_candidate_pairs":1})
    index,settings=inputs([alert(str(i),host="h") for i in range(6)])
    original=Path.open
    def tripwire(path,*args,**kwargs):
        assert "evaluation" not in [p.lower() for p in path.parts]
        assert path.name.lower() not in {"labels.csv","attacks.log","gold_chain.json"}
        return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,"open",tripwire)
    result=run(index,settings,config,output_root=tmp_path)
    assert result.record.candidate_truncated and result.record.status.value=="incomplete"
    assert not result.record.is_complete
    assert result.record.errors


def test_resource_interruption_never_publishes_partial_maximum(config,monkeypatch):
    import app.correlation.edges as module
    index,settings=inputs(parent_child())
    monkeypatch.setattr(module,"generate_candidates",lambda *args: (_ for _ in ()).throw(MemoryError()))
    result=run(index,settings,config)
    assert result.record.status.value=="incomplete"
    assert result.record.incomplete_reason=="correlation_resource_exhausted"
    assert result.edges==[]


def test_fixture_positive_with_unchanged_v0_parameters(config):
    # Rarity uses the entire analysis population. Background facts give the
    # attested parent-child context nontrivial rarity without changing any v0
    # threshold, weight, guard or independence declaration.
    positives=parent_child()
    background=[alert("synthetic-background-"+str(i),20000+i*9000,host="isolated-"+str(i)) for i in range(8)]
    index,settings=inputs(positives+background)
    result=run(index,settings,config)
    assert len(result.edges)==1
    edge=result.edges[0]
    assert {edge.source_alert_id,edge.target_alert_id}=={a.alert_id for a in positives}
    assert edge.score>=config.algorithm.score.correlation_threshold==.65
    assert edge.score_breakdown.relation_score==1.0
    mapped=config.algorithm.chain.relation_type_mapping["parent_child_process"]
    assert result.summary["relation_type_distribution"]=={mapped:1}
    assert result.record.is_complete


def test_high_score_without_chain_relation_still_admits_correlation(config):
    # User-confirmed distinction: no attested propagation means no ChainEdge,
    # but sufficiently supported undirected CorrelationEdge remains legal.
    web=alert("synthetic-web",category="web_attack",host="h",account="u",session="s")
    proc=alert("synthetic-proc",1,category="process_execution",host="h",account="u",session="s")
    background=[alert("unrelated-"+str(i),20000+i*9000,host="scope-"+str(i)) for i in range(98)]
    index,settings=inputs([web,proc,*background])
    result=run(index,settings,config)
    assert len(result.edges)==1
    edge=result.edges[0]
    assert edge.score>=config.algorithm.score.correlation_threshold
    assert edge.score_breakdown.relation_score==0 and edge.score_breakdown.source_score==0
    assert all(reason.code.value!="explicit_relation" for reason in edge.reasons)
    assert result.summary["relation_type_distribution"]=={"unresolved":1}


@pytest.mark.skipif(os.environ.get("TRACEBACK_FULL_DATASET")!="1",reason="explicit full-dataset stage run; run with TRACEBACK_FULL_DATASET=1")
def test_full_russellmitchell_stage_replay(monkeypatch):
    """Re-execute all 45,501 representatives; compare ordered score/evidence.

    This is an actual opt-in stage check, separate from quick fixture tests. It
    reuses Task 02 production outputs and never loads evaluation labels.
    """
    import builtins
    from hashlib import sha256
    import json
    import duckdb
    from app.services.storage import SnapshotStore, read_preprocessing
    from app.correlation.edges import ALGORITHM_VERSION
    from app.utils.stable_id import id_for
    root=Path(__file__).resolve().parents[2]
    original_open,original_path_open=builtins.open,Path.open
    def checked(path):
        if isinstance(path,(str,Path)):
            value=Path(path)
            assert "evaluation" not in {part.lower() for part in value.parts}
            assert value.name.lower() not in {"labels.csv","attacks.log","gold_chain.json"}
    def open_tripwire(path,*args,**kwargs):
        checked(path)
        return original_open(path,*args,**kwargs)
    def path_tripwire(path,*args,**kwargs):
        checked(path)
        return original_path_open(path,*args,**kwargs)
    monkeypatch.setattr(builtins,"open",open_tripwire)
    monkeypatch.setattr(Path,"open",path_tripwire)
    pre_id=os.environ["TRACEBACK_PREPROCESSING_ANALYSIS_ID"]
    values,config,settings,manifest=read_preprocessing(root,pre_id)
    assert len(values["alerts"])==45510 and len(values["dedupe_groups"])==9 and len(values["entities"])==13752
    analysis_id=id_for("AnalysisRecord",{"input_alert_ids":[a.alert_id for a in values["alerts"]],
        "config_hash":manifest["config_hash"],"algorithm_version":ALGORITHM_VERSION,"schema_version":"1.0"})
    store=SnapshotStore(root,analysis_id)
    first,frequency,details=store.read_metadata()
    original_edges=[e.canonical_json() for e in store.read_records("correlation_edges")]
    def semantic_digest():
        digest=sha256();counts={"candidate":0,"member_score":0,"correlation_decision":0}
        with (store.details/"diagnostics.jsonl").open(encoding="utf-8") as handle:
            for line in handle:
                row=json.loads(line)
                stage=row["stage"]
                if stage in counts:
                    counts[stage]+=1
                    if stage=="candidate":
                        # Retrieval diagnostics may gain additional matching
                        # channels/entities during implementation. The replay
                        # contract compares candidate membership/channels and
                        # the complete scored Reason/evidence identity below.
                        selected={k:row[k] for k in ("support_key","channels")}
                    elif stage=="member_score":
                        selected={k:row[k] for k in ("support_key","support_pair","values","contributions","raw_total","score", "source_independence","valid","rejection_codes","reasons")}
                    else:
                        selected=row
                    digest.update(json.dumps(selected,sort_keys=True,ensure_ascii=False,separators=(",",":"),allow_nan=False).encode("utf-8"))
                    digest.update(b"\n")
        return digest.hexdigest(),counts
    expected_hash,expected_counts=semantic_digest()
    # Reverse all collection inputs; canonical ID ordering must recover the
    # same candidates, full member scores, reasons and formal result set.
    result=run_correlation(list(reversed(values["alerts"])),list(reversed(values["dedupe_groups"])),
                           list(reversed(values["entities"])),config,settings,output_root=root,
                           progress=lambda row: print(json.dumps(row,sort_keys=True),flush=True))
    assert [e.canonical_json() for e in result.edges]==original_edges
    assert result.record.analysis_id==first.analysis_id and result.record.dataset_digest==first.dataset_digest
    assert semantic_digest()==(expected_hash,expected_counts)
    assert result.summary["representative_alert_count"]==45501
    assert result.summary["verified_member_pair_count"]>=result.summary["candidate_pair_count"]
    record,new_frequency,new_details=store.read_metadata()
    assert new_frequency==frequency
    assert new_details["summary"]["candidate_pair_count"]==expected_counts["candidate"]
    assert expected_counts["candidate"]==expected_counts["correlation_decision"]
    with duckdb.connect(str(store.domain/"domain.duckdb"),read_only=True) as db:
        assert db.execute("SELECT count(*) FROM alerts").fetchone()[0]==45510
        assert db.execute("SELECT count(*) FROM dedupe_groups").fetchone()[0]==9
        assert db.execute("SELECT count(*) FROM entities").fetchone()[0]==13752
        assert db.execute("SELECT count(*) FROM correlation_edges").fetchone()[0]==len(result.edges)
        assert {row[0] for row in db.execute("SHOW TABLES").fetchall()}=={"alerts","dedupe_groups","entities","correlation_edges"}
    assert record.candidate_truncated and record.status.value=="incomplete"
    print(json.dumps({"analysis_id":analysis_id,"semantic_replay_digest":expected_hash,"counts":expected_counts,
                      "summary":result.summary},sort_keys=True),flush=True)
