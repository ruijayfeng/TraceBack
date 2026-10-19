"""Task 09.1 representative metrics; A/B/C/D are synthetic, not dataset claims."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from app.api.incident_metrics import incident_metrics
from test_workbench import api
from test_api import create_run
from test_analysis_service import edge_records
from test_wazuh_adapter import synthetic_record


@pytest.mark.parametrize('members,groups,expected', [
    (['a'], [], (1,0,0)),
    (['a1','a2'], [('a1',['a1','a2'])], (1,0,1)),
    (['a','b'], [], (0,1,0)),
    (['a1','a2','b'], [('a1',['a1','a2'])], (0,1,1)),
])
def test_fixture_semantics(members,groups,expected):
    incidents=[SimpleNamespace(alert_ids=members)]
    groups=[SimpleNamespace(representative_alert_id=r,alert_ids=ids) for r,ids in groups]
    result=incident_metrics(incidents,groups)
    assert tuple(result.values())==expected
    assert result['representative_singleton_incident_count']+result['correlated_multi_alert_incident_count']==len(incidents)


@pytest.mark.parametrize('fixture,expected', [('A',(1,0,0)),('B',(1,0,1)),('C',(0,1,0)),('D',(0,1,1))])
def test_formal_pipeline_and_sql_metrics(api,fixture,expected):
    records=edge_records() if fixture in {'C','D'} else [synthetic_record()]
    # Complete declared payload fields allow actual complete-link dedupe.
    for i,r in enumerate(records):
        r.setdefault('data',{}).update(src_ip='192.0.2.1',dest_ip='192.0.2.2',src_port=1000,dest_port=80,url=f'/synthetic/{i}')
    if fixture in {'B','D'}:
        duplicate=deepcopy(records[0]); duplicate['id']='synthetic-duplicate'
        records.append(duplicate)
    client,_,_=api
    aid=create_run(api,records)
    counts=client.get(f'/api/v1/analyses/{aid}/overview').json()['counts']
    names=('representative_singleton_incident_count','correlated_multi_alert_incident_count','incidents_with_dedupe_expansion_count')
    assert tuple(counts[k] for k in names)==expected
    assert counts[names[0]]+counts[names[1]]==counts['incident_count']
    rows=client.get(f'/api/v1/analyses/{aid}/workbench').json()['items']
    assert len(rows)==1
    row=rows[0]
    assert row['representative_member_count']==(1 if fixture in {'A','B'} else 2)
    assert row['has_dedupe_expansion']==(fixture in {'B','D'})
    if fixture in {'C','D'}:
        iid=row['incident']['incident_id']
        incident=client.get(f'/api/v1/incidents/{iid}',params={'analysis_id':aid}).json()['incident']
        assert incident['correlation_edge_ids']
    for kind,expected_total in [('singleton',expected[0]),('multi_alert',expected[1])]:
        assert client.get(f'/api/v1/analyses/{aid}/workbench',params={'kind':kind}).json()['total']==expected_total
