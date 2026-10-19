"""Scope collisions, shared deployment network and literal command semantics."""

from dataclasses import replace

import pytest

from app.adapters import WazuhAdapter
from app.entities.extraction import extract_entities
from app.models import EntityType
from test_wazuh_adapter import config, settings, synthetic_record


@pytest.mark.parametrize("field,kind,expected", [("src_ip",EntityType.IP,0),("host",EntityType.HOST,1),
    ("dstuser",EntityType.ACCOUNT,2)])
def test_observed_identity_scopes_without_dataset_namespace(config,field,kind,expected):
    sa,sb=settings("synthetic.a"),settings("synthetic.b")
    data={field:"192.0.2.1" if kind==EntityType.IP else "same-value"}
    result=extract_entities([WazuhAdapter(config,s).convert(synthetic_record(data=data)) for s in (sa,sb)],
                            {s.source_namespace:s for s in (sa,sb)})
    assert len([e for e in result.entities if e.type==kind]) == expected


def test_network_metadata_does_not_promote_endpoint_ip_to_entity(config):
    sa,sb=settings("synthetic.a",network_namespace="synthetic.network"),settings("synthetic.b",network_namespace="synthetic.network")
    alerts=[WazuhAdapter(config,s).convert(synthetic_record(data={"src_ip":"2001:DB8::1"})) for s in (sa,sb)]
    result=extract_entities(alerts,{s.source_namespace:s for s in (sa,sb)})
    assert not result.entities
    assert all(a.src_ip == '2001:db8::1' for a in result.alerts)


def test_file_and_command_host_scopes_and_literal_values(config):
    s=settings();adapter=WazuhAdapter(config,s)
    command="Echo 'MiXeD Case' --X=A"
    alerts=[adapter.convert(synthetic_record(data={"host":host,"file":"/Case/File","command":command})) for host in ("host-a","host-b")]
    result=extract_entities(alerts,{s.source_namespace:s})
    files=[e for e in result.entities if e.type==EntityType.FILE]
    commands=[e for e in result.entities if e.type==EntityType.COMMAND]
    assert files == commands == []
    assert all(a.command == command and a.file == '/Case/File' for a in result.alerts)


def test_short_host_not_fqdn_and_domain_global(config):
    sa,sb=settings("synthetic.a"),settings("synthetic.b")
    alerts=[WazuhAdapter(config,s).convert(synthetic_record(data={"host":host,"http":{"hostname":"EXAMPLE.COM."}}))
            for s,host in ((sa,"host"),(sb,"host.example.com"))]
    result=extract_entities(alerts,{s.source_namespace:s for s in (sa,sb)})
    assert len([e for e in result.entities if e.type==EntityType.HOST])==2
    domain=[e for e in result.entities if e.type==EntityType.DOMAIN]
    assert domain == []
    assert all(a.domain == 'example.com' for a in result.alerts)


def test_account_case_and_explicit_realm(config):
    sa=settings("synthetic.a",account_realm="synthetic.realm");sb=replace(sa,source_namespace="synthetic.b")
    alerts=[WazuhAdapter(config,s).convert(synthetic_record(data={"dstuser":user})) for s,user in ((sa,"Admin"),(sb,"Admin"),(sb,"admin"))]
    result=extract_entities(alerts,{s.source_namespace:s for s in (sa,sb)})
    accounts=[e for e in result.entities if e.type==EntityType.ACCOUNT]
    assert len(accounts)==2 and {e.value for e in accounts}=={"Admin","admin"}
