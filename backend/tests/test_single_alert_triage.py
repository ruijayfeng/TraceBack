"""Deterministic singleton SOC value without risk-to-correlation feedback."""

from pathlib import Path

import pytest

from app.config import load_config
from app.correlation.edges import run_correlation
from app.chains.assembly import run_reconstruction
from app.incidents.triage import triage_singletons
from app.models import Incident
from app.services.storage import SnapshotStore
from test_correlation_score import alert, inputs


ROOT=Path(__file__).resolve().parents[2]


def pipeline(alerts):
    config=load_config(ROOT/"configs/algorithm-v2.yaml")
    index,settings=inputs(alerts)
    c=run_correlation(index.alerts.values(),(),index.entities.values(),config,settings)
    r=run_reconstruction(index.alerts.values(),(),index.entities.values(),c.edges,config,settings,upstream_record=c.record)
    incidents=triage_singletons(r.incidents,index,config,c.summary,search_complete=r.record.is_complete)
    return incidents,index,c,r


@pytest.mark.parametrize("severity,level,priority", [("high","high","P2"),("critical","critical","P1"),
                                                   ("low","low","P4"),("unknown","unknown","UNRATED")])
def test_priority_and_bound_evidence(severity,level,priority):
    incidents,index,c,_=pipeline([alert("single",severity=severity)])
    triage=incidents[0].single_alert_triage
    assert triage.risk_level==level and triage.recommended_priority==priority
    assert triage.formal_edge_count==0 and c.edges==[]
    assert triage.candidate_count==0 and triage.correlation_diagnostic
    assert Incident.model_validate_json(incidents[0].canonical_json())==incidents[0]
    for p in triage.evidence_refs:
        p.resolve(index.alerts)


def test_missing_context_not_fabricated_and_rarity_alone_capped():
    incidents,_,_,_=pipeline([alert("single",rule_id="rare"),alert("other",rule_id="other")])
    for i in incidents:
        t=i.single_alert_triage
        assert t.risk_level=="low" and t.single_alert_risk_score<=.3
        assert set(t.unavailable_evidence)=={"severity","category"}
        assert {r.field for r in t.risk_reasons}=={"rarity"}


def test_high_risk_singletons_remain_unrelated_and_storage_roundtrip(tmp_path):
    incidents,index,c,r=pipeline([alert("a",host="a",severity="critical"),alert("b",host="b",severity="critical")])
    assert len(incidents)==2 and not c.edges
    assert all(i.single_alert_triage.risk_level=="critical" for i in incidents)
    store=SnapshotStore(tmp_path,c.record.analysis_id)
    store.write_records("incidents",incidents)
    assert list(store.read_records("incidents"))==incidents
    store.write_records("alerts",index.alerts.values())
    assert all(not chain.edges for chain in r.chains)


def test_resource_incomplete_diagnostic_is_honest():
    incidents,index,c,_=pipeline([alert("single",severity="high")])
    cfg=load_config(ROOT/"configs/algorithm-v2.yaml")
    value=triage_singletons(incidents,index,cfg,c.summary,search_complete=False)[0].single_alert_triage
    assert not value.search_complete and "不完整" in value.correlation_diagnostic
