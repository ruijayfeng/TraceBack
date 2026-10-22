"""Core entity whitelist, evidence closure, idempotence and existing lineage."""

from app.adapters import WazuhAdapter
from app.entities.extraction import extract_entities
from app.models import EntityType, AlertRelationType
from app.models.base import resolve_pointer
from test_wazuh_adapter import config, settings, synthetic_record


def full_record():
    return synthetic_record(data={
        "host":"Synthetic.Host.","src_ip":"2001:0DB8:0:0::1", "dest_ip":"192.0.2.2",
        "dstuser":"Admin", "session":"synthetic-session", "domain":"unused",
        "http":{"hostname":"EXAMPLE.COM.", "url":"HTTPS://EXAMPLE.COM:443/Path?q=A#frag"},
        "process":{"name":"Worker","pid":"100","start_time":"2022-01-20T00:00:00Z"},
        "parent_process":{"name":"Parent","pid":"99","start_time":"2022-01-19T00:00:00Z"},
        "file":"C:/CaseSensitive/FILE", "command":"Echo 'Mixed Case' --Arg=X",
    })


def test_core_types_and_references(config):
    s=settings();a=WazuhAdapter(config,s).convert(full_record())
    result=extract_entities([a],{s.source_namespace:s})
    assert {e.type for e in result.entities} == {EntityType.HOST, EntityType.ACCOUNT, EntityType.PROCESS}
    assert result.alerts[0].src_ip == '2001:db8::1'
    assert result.alerts[0].contexts[0].kind == 'session'
    assert result.alerts[0].raw_alert == full_record()
    assert len(result.alerts) == 1 and result.alerts[0].alert_id == a.alert_id
    assert set(result.alerts[0].entity_ids) == {e.entity_id for e in result.entities}
    for entity in result.entities:
        assert entity.alert_ids == [a.alert_id]
    for occurrence in result.alerts[0].entity_occurrences:
        resolve_pointer(a.raw_alert,occurrence.raw_pointer)
    assert result.alerts[0].relations[0].relation_type == AlertRelationType.PARENT_CHILD_PROCESS
    assert extract_entities(result.alerts,{s.source_namespace:s}) == result


def test_common_entities_merge_and_original_display_minimum_alert(config):
    s=settings();adapter=WazuhAdapter(config,s)
    a=adapter.convert(synthetic_record(id="a",data={"host":"HOST."}))
    b=adapter.convert(synthetic_record(id="b",data={"host":"host"}))
    first=extract_entities([a,b],{s.source_namespace:s})
    second=extract_entities([b,a],{s.source_namespace:s})
    assert first == second and len(first.entities) == 1
    assert first.entities[0].value == "host"
    expected=min([a,b],key=lambda a:a.alert_id).raw_alert["data"]["host"]
    assert first.entities[0].display_value == expected


def test_process_description_and_pid_only_do_not_invent_instances(config):
    s=settings();adapter=WazuhAdapter(config,s)
    alerts=[adapter.convert(synthetic_record(id=str(i),data={"host":"h","process":{"pid":7}})) for i in range(2)]
    result=extract_entities(alerts,{s.source_namespace:s})
    # Incomplete PID observations are retained individually, not certified as a
    # common process instance merely because host and PID happen to agree.
    assert len([e for e in result.entities if e.type==EntityType.PROCESS]) == 2
    assert set(result.alerts[0].entity_ids).intersection(result.alerts[1].entity_ids) == {
        e.entity_id for e in result.entities if e.type==EntityType.HOST}
    assert all(not a.relations for a in result.alerts)
    raw=full_record();del raw["data"]["process"]["start_time"]
    result=extract_entities([adapter.convert(raw)],{s.source_namespace:s})
    assert not result.alerts[0].relations
    assert all(e.value != 'Worker' for e in result.entities)
    assert result.alerts[0].process.name == 'Worker'


def test_host_time_category_request_cooccurrence_has_no_causal_relation(config):
    s=settings();raw=full_record();del raw["data"]["parent_process"]
    raw["data"]["request_id"]="same-request"
    alert=WazuhAdapter(config,s).convert(raw)
    assert extract_entities([alert],{s.source_namespace:s}).alerts[0].relations == []


def test_process_pid_reuse_start_time_changes_identity(config):
    s=settings();adapter=WazuhAdapter(config,s)
    a=full_record();b=full_record();b["data"]["process"]["start_time"]="2022-01-21T00:00:00Z"
    result=extract_entities([adapter.convert(a),adapter.convert(b)],{s.source_namespace:s})
    assert len([e for e in result.entities if e.type==EntityType.PROCESS]) == 3


def test_invalid_parent_instance_chronology_does_not_create_lineage(config):
    s=settings();raw=full_record()
    raw["data"]["parent_process"]["start_time"]="2022-01-21T00:00:00Z"
    result=extract_entities([WazuhAdapter(config,s).convert(raw)],{s.source_namespace:s})
    assert not result.alerts[0].relations
