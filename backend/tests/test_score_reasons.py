"""Recompute serialized contributions and resolve every bound pointer."""

import pytest
from app.correlation.reasons import make_reason
from app.correlation.scoring import CorrelationScorer
from app.models import EvidencePointer, Reason
from app.utils.stable_id import id_for
from test_correlation_score import alert, config, inputs, parent_child


def test_reason_identity_and_pointer_closure(config):
    index,settings=inputs(parent_child())
    scorer=CorrelationScorer(index,config,settings)
    result=scorer.score_pair(*index.alerts)
    for reason in result.reasons:
        assert reason.reason_id==id_for("Reason",reason)
        assert Reason.model_validate_json(reason.canonical_json(),context={"alerts":index.alerts})==reason
        assert set(reason.alert_ids)==set(index.alerts)
        for p in reason.params.get("raw_pointers",[]):
            assert EvidencePointer.model_validate(p).resolve(index.alerts) is not None
    breakdown=scorer.breakdown(result)
    assert sum(breakdown.contributions.model_dump().values())==pytest.approx(breakdown.raw_total,abs=.00001)
    assert breakdown.final_score==pytest.approx(min(1,max(0,breakdown.raw_total)),abs=.00001)


def test_cross_alert_pointer_wrong_binding_rejected(config):
    index,_=inputs([alert("a",host="h"),alert("b",host="h")])
    a,b=list(index.alerts)
    with pytest.raises(ValueError):
        make_reason("explicit_relation",[a],{"relation_type":"session_continuity","raw_pointers":[
            {"alert_id":b,"pointer":"/source_record_id","side":"src"}]},context={"alerts":index.alerts})
