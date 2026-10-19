"""Frozen duplicate semantics and independent small-input exhaustive oracle."""

from dataclasses import replace
from itertools import combinations
import math

import pytest

from app.adapters import WazuhAdapter
from app.dedup.grouping import DuplicateScorer, deduplicate
from app.utils.stable_id import id_for
from test_wazuh_adapter import config, settings, synthetic_record


def request_record(identity,second=0,**changes):
    data={"src_ip":"192.0.2.1","dest_ip":"192.0.2.2","src_port":1234,"dest_port":80,
          "host":"synthetic-target","http":{"url":"/Request?X=A"}}
    data.update(changes)
    return synthetic_record(id=identity,timestamp=f"2022-01-21T00:00:{second:02d}Z",data=data)


def make(config, records):
    s=settings();adapter=WazuhAdapter(config,s)
    return [adapter.convert(r) for r in records],{s.source_namespace:s}


def test_near_duplicate_minimum_score_representative_and_order(config):
    alerts,sources=make(config,[request_record(str(i),t) for i,t in enumerate((0,5,10))])
    first=deduplicate(alerts,config,sources)
    second=deduplicate(list(reversed(alerts)),config,sources)
    assert first==second and len(first.groups)==1
    group=first.groups[0]
    assert group.alert_ids==sorted(a.alert_id for a in alerts)
    assert group.representative_alert_id==min(group.alert_ids)
    assert group.group_id==id_for("DedupeGroup",{"alert_ids":group.alert_ids})
    assert group.duplicate_score==0.95
    assert len(group.reasons)==3
    # Output is a view: the caller's complete CanonicalAlerts remain unchanged.
    assert len(alerts)==3 and all(a.raw_alert for a in alerts)


def test_complete_link_no_transitive_abc_merge(config):
    alerts,sources=make(config,[request_record(str(i),t) for i,t in enumerate((0,15,30))])
    result=deduplicate(alerts,config,sources)
    assert len(result.groups)==1 and len(result.groups[0].alert_ids)==2
    assert any(d.get("decision")=="reject" for d in result.diagnostics)
    assert result.verified_pair_count==3  # includes A-C even if it was not a qualifying pair


@pytest.mark.parametrize("change", [
    {"http":{"url":"/Other?X=A"}}, {"dest_ip":"192.0.2.3"}, {"host":"different-target"},
    {"src_port":4321}, {"http":{}}, {"dest_port":None,"host":None},
])
def test_same_ip_same_category_insufficient(config,change):
    alerts,sources=make(config,[request_record("a"),request_record("b",1,**change)])
    assert deduplicate(alerts,config,sources).groups==[]


def test_time_window_boundaries_and_exact_origin_not_window_limited(config):
    alerts,sources=make(config,[request_record("a"),request_record("b",30),request_record("c",31)])
    scorer=DuplicateScorer(alerts,config,sources)
    pairs,_=scorer.candidates()
    assert tuple(sorted((alerts[0].alert_id,alerts[1].alert_id))) in pairs
    assert tuple(sorted((alerts[0].alert_id,alerts[2].alert_id))) not in pairs
    raw_a=request_record("a");raw_b=request_record("b",45)
    for r in (raw_a,raw_b):
        r.update(origin_namespace="synthetic.origin",origin_record_id="actual-origin-id")
    alerts,sources=make(config,[raw_a,raw_b])
    result=deduplicate(alerts,config,sources)
    assert len(result.groups)==1 and result.groups[0].duplicate_score==1


def test_reused_source_id_and_origin_conflicts_are_not_merged(config):
    alerts,sources=make(config,[request_record("reused"),request_record("reused",1)])
    result=deduplicate(alerts,config,sources)
    assert result.groups==[]
    assert any(d.get("code")=="source_record_id_conflict" for d in result.diagnostics)
    raw_a=request_record("a");raw_b=request_record("b",1,dest_ip="192.0.2.3")
    for r in (raw_a,raw_b):
        r.update(origin_namespace="synthetic.origin",origin_record_id="id")
    alerts,sources=make(config,[raw_a,raw_b])
    assert deduplicate(alerts,config,sources).groups==[]


def test_native_id_not_shared_between_source_namespaces(config):
    sa,sb=settings("synthetic.a"),settings("synthetic.b")
    raw=request_record("same-native-id")
    alerts=[WazuhAdapter(config,s).convert(raw) for s in (sa,sb)]
    assert deduplicate(alerts,config,{s.source_namespace:s for s in (sa,sb)}).groups==[]


def test_singleton_no_group_and_missing_payload_scores(config):
    alerts,sources=make(config,[request_record("a",http={}),request_record("b",1,http={})])
    scorer=DuplicateScorer(alerts,config,sources)
    value=scorer.score(alerts[0].alert_id,alerts[1].alert_id)
    assert value["score"] <= 0.65 and not value["qualifies"]
    assert deduplicate(alerts[:1],config,sources).groups==[]


def test_many_unrelated_payload_buckets_avoid_all_window_pairs(config):
    alerts,sources=make(config,[request_record(str(i),http={"url":"/"+str(i)}) for i in range(150)])
    result=deduplicate(alerts,config,sources)
    assert result.candidate_count==result.verified_pair_count==0


def test_indexed_groups_match_small_exhaustive_oracle(config):
    alerts,sources=make(config,[request_record(str(i),t) for i,t in enumerate((0,3,8,17,30,45))])
    scorer=DuplicateScorer(alerts,config,sources)
    all_pairs=list(combinations(sorted(a.alert_id for a in alerts),2))
    ranked=sorted(all_pairs,key=lambda p:(-scorer.score(*p)["score"],p))
    groups=[{a.alert_id} for a in alerts]
    for left,right in ranked:
        ga=next(g for g in groups if left in g);gb=next(g for g in groups if right in g)
        if ga is gb:
            continue
        if all(scorer.score(x,y)["qualifies"] for x in ga for y in gb):
            merged=ga|gb
            groups=[g for g in groups if g is not ga and g is not gb]+[merged]
    expected=sorted(sorted(g) for g in groups if len(g)>1)
    actual=deduplicate(alerts,config,sources)
    assert sorted(g.alert_ids for g in actual.groups)==expected


def test_mixed_exact_and_approximate_group_uses_all_pairs_min(config):
    records=[request_record(str(i),t) for i,t in enumerate((0,5,10))]
    for r in records[:2]:
        r.update(origin_namespace="synthetic.origin",origin_record_id="native")
    alerts,sources=make(config,records)
    result=deduplicate(alerts,config,sources)
    assert len(result.groups)==1 and result.groups[0].duplicate_score==0.95
    assert sorted(r.params["similarity"] for r in result.groups[0].reasons)==[0.95,round(0.9+0.1*math.sqrt(0.5),6),1]


def test_resource_exhaustion_cannot_publish_complete_groups(config,monkeypatch):
    alerts,sources=make(config,[request_record("a"),request_record("b",1)])
    def exhausted(self):
        raise MemoryError("synthetic resource failure")
    monkeypatch.setattr(DuplicateScorer,"candidates",exhausted)
    result=deduplicate(alerts,config,sources)
    assert result.groups==[] and not result.is_complete
    assert result.incomplete_reason=="dedupe_resource_exhausted"
