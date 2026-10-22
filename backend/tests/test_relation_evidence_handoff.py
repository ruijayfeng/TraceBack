"""Synthetic role and network acceptance evidence; no benchmark fixtures."""
import pytest
from app.stage_evidence import load_evidence_config
from test_community_builder import cfg, normalization, record, ROOT
from test_stage_candidates import source
from test_stage_evidence import verify
from test_context_identity_handoff import contract
from test_identity_projection import HOST


def decision(result,data,native_a,native_b):
    owners={a.raw_alert['event_id']:s.stage_id for s in data.stages.stages
            for a in data.alerts if a.alert_id in s.alert_ids}
    return next(d for d in result.decisions if {d.stage_a_id,d.stage_b_id}=={owners[str(native_a)],owners[str(native_b)]})


@pytest.mark.parametrize('third_current',[False,True])
def test_parent_only_reference_does_not_pollute_current_process_pair(cfg,normalization,third_current):
    instance=dict(hostname='h',process_id=7,process_start_time='2025-12-31T00:00:00Z')
    rows=[record(1,operation='ProcessStart',**instance),record(2,time=10,operation='FileRead',**instance),
          record(3,time=20,operation='NetworkConnection',**(instance if third_current else dict(hostname='h',
              process_id=8,process_start_time='2026-01-01T00:00:15Z',parent_process_id=7,
              parent_process_start_time='2025-12-31T00:00:00Z')))]
    data=source(rows,cfg,normalization)
    result=verify(data,cfg,load_evidence_config(ROOT/'configs/stage-evidence-v1.yaml'))
    d=decision(result,data,1,2)
    assert d.relation_type==('NO_RELATION' if third_current else 'UNDIRECTED_EDGE')
    assert d.from_stage_id is None and d.to_stage_id is None


@pytest.mark.parametrize('mode',['valid','reversed','failed','endpoint','authority','unknown'])
def test_network_initiation_to_auth_acceptance_uses_typed_roles(cfg,normalization,mode):
    rows=[record(1,hostname='client',host_id='client-asset',operation='NetworkConnection',
                 connection_id='connection-X',src_ip='192.0.2.1',src_port=1234,dst_ip='192.0.2.2',dst_port=22,protocol='TCP'),
          record(2,'authentication',time=5,host='server',host_id='server-asset',host_ip='192.0.2.2',
                 operation='credential_accepted',connection_id='connection-X',source_ip='192.0.2.1',source_port=1234,destination_port=22)]
    contracts={'edr':dict(host=HOST,contexts=[contract()]),
               'authentication':dict(host=HOST,contexts=[{**contract(),'destination_ip_pointer':'/host_ip'}])}
    if mode=='reversed': rows[1]['timestamp']=record(2,time=-5)['timestamp']
    if mode=='failed': rows[1]['operation']='login_failed'
    if mode=='endpoint': rows[1]['source_port']=999
    if mode=='authority': contracts['authentication']['contexts'][0]['authority_domain']='other'
    if mode=='unknown': rows[0]['operation']='observed'
    data=source(rows,cfg,normalization,overrides={s:dict(identity_authorities=c) for s,c in contracts.items()})
    result=verify(data,cfg,load_evidence_config(ROOT/'configs/stage-evidence-v1.yaml'))
    d,=result.decisions
    assert (d.relation_type=='DIRECTED_EDGE')==(mode=='valid')
    if mode=='valid':
        initiating=next(s.stage_id for s in data.stages.stages if any(a.raw_alert['event_id']=='1' and a.alert_id in s.alert_ids for a in data.alerts))
        assert d.from_stage_id==initiating
        assert any(c.evidence_type=='CONNECTION_ESTABLISH_ACCEPT' and c.valid for c in result.claims)
        by_id={a.alert_id:a for a in data.alerts}
        refs=[r for c in result.claims if c.evidence_type=='CONNECTION_ESTABLISH_ACCEPT'
              for oid in c.observation_ids for r in result.trace.resolve_observation(oid,by_id)]
        assert {'/src_ip','/src_port','/dst_ip','/dst_port','/protocol','/connection_id','/operation','/host_ip'}<={r['pointer'] for r in refs}
