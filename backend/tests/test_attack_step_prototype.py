"""Independent prototype tests; synthetic typed facts, no Ground Truth inputs."""
import copy
import json
import os
from pathlib import Path
import sys

import pytest
from app.attack_steps.candidate import generate
from app.attack_steps.evidence import checked_reference,descriptors,p1_proof,reference
from app.attack_steps.grouping import build_groups,components,evaluate
from app.attack_steps.guard import ReadOnlyGuard
from app.attack_steps.loader import build_indexes,file_digests,load_inputs,signature
from app.attack_steps.models import P1,Proposal,PrototypeError,Snapshot,VERSIONS,jcs,run_id,sha
from app.attack_steps.prototype import compute,execute
from app.attack_steps.validation import envelope,validate
from app.utils.stable_id import content_digest

ROOT=Path(__file__).resolve().parents[2]
def identity(prefix,n): return prefix+'_'+format(n,'064x')

def synthetic(count=2,p1=True):
    """Serialized source tables, not a fake semantic output claiming validation."""
    ids=[identity('stg',x+1) for x in range(count)]
    alerts=[identity('alt',x+1) for x in range(count)]
    scope=json.dumps(dict(kind='request',namespace='synthetic.request.authority',host_scope='synthetic.host.epoch'))
    req=dict(subtype='request',scope=scope,value='synthetic-request')
    stages=[]; aa=[]; annotations=[]; claims=[]; obs=[]; pointers=[]; checks=[]; decisions=[]
    for pos,(sid,aid) in enumerate(zip(ids,alerts,strict=True)):
        aa.append(dict(alert_id=aid,raw_alert=dict(request_id='synthetic-request',operation='request' if pos%2==0 else 'response'),
            entity_ids=[],entity_occurrences=[],identity_binding_ids=[],field_provenance={},
            contexts=[dict(kind='request',scope=scope,value='synthetic-request',raw_pointer='/request_id')],
            source_type='synthetic',source_namespace='synthetic',alert_type='request' if pos%2==0 else 'response',category='observed',
            timestamp='2026-01-01T00:00:00Z',command=None,url=None,file=None,process=None,parent_process=None))
        stages.append(dict(stage_id=sid,community_id=identity('com',1),behavior='EXECUTION' if pos else 'NETWORK_ACTIVITY',
            alert_ids=[aid],alert_count=1,start_time='2026-01-01T00:00:00Z',end_time='2026-01-01T00:00:00Z',
            host_entities=[],account_entities=[],process_entities=[],flow_bindings=[],session_bindings=[],
            request_bindings=['request:synthetic'],task_bindings=[],source_types=['synthetic'],aggregation_basis=[],evidence_summary='Synthetic observed activity.'))
        annotations.append(dict(alert_id=aid,behavior=stages[-1]['behavior'],evidence=[]))
    for pos in range(count-1):
        cid=identity('ecl',pos+1); oid=identity('obs',pos+1); vid=identity('evc',pos+1); rid=identity('scp',pos+1)
        pids=[]
        for side in [pos,pos+1]:
            pid=identity('erp',len(pointers)+1); pids.append(pid)
            pointers.append(dict(pointer_id=pid,raw_pointer=dict(alert_id=alerts[side],pointer='/request_id',side='shared')))
        checks.append(dict(validation_id=vid,valid=True,conflict_status=[],temporal_check=dict(status='CONSISTENT')))
        obs.append(dict(observation_id=oid,alert_a_id=alerts[pos],alert_b_id=alerts[pos+1],raw_pointer_ids=pids,validation_id=vid))
        claims.append(dict(claim_id=cid,stage_a_id=ids[pos],stage_b_id=ids[pos+1],evidence_type='REQUEST_RESPONSE' if p1 else 'PARENT_CHILD_PROCESS',
            semantic_class='DIRECTIONAL_RELATION',identity=copy.deepcopy(req),direction_claim='A_TO_B',role_a='REQUEST' if p1 else 'PARENT',role_b='RESPONSE' if p1 else 'CHILD',
            valid=True,temporal_check=dict(status='CONSISTENT'),conflict_status=[],reason='Synthetic explicit typed evidence.',observation_ids=[oid],
            context_identity_id=None,metadata=dict(projection_identity=copy.deepcopy(req))))
        decisions.append(dict(candidate_id=rid,stage_a_id=ids[pos],stage_b_id=ids[pos+1],relation_type='DIRECTED_EDGE',
            direction_claim='A_TO_B',from_stage_id=ids[pos],to_stage_id=ids[pos+1],primary_claim_id=cid,
            relation_claim_ids=[cid],context_claim_ids=[],supporting_claim_ids=[],invalid_claim_ids=[],context_identity_ids=[],reason='Synthetic accepted relation.'))
        if p1 and pos%2:
            claims[-1].update(direction_claim='B_TO_A',role_a='RESPONSE',role_b='REQUEST')
            decisions[-1].update(direction_claim='B_TO_A',from_stage_id=ids[pos+1],to_stage_id=ids[pos])
    source=dict(alerts=aa,entities=[],identity_projection=dict(host_alias_bindings=[],auth_session_bindings=[],context_bindings=[],process_bindings=[]),
        communities=dict(contract_version=VERSIONS['community'],config_hash='1'*64,incident_candidates=[dict(community_id=identity('com',1),alert_ids=alerts)]),
        stages=dict(contract_version=VERSIONS['stages'],config_hash='2'*64,stages=stages,behaviors=annotations),
        candidates=dict(contract_version=VERSIONS['candidates'],config_hash='3'*64,candidates=[],features=[]),
        evidence=dict(contract_version=VERSIONS['evidence'],config_hash='4'*64,decisions=decisions,claims=claims,context_postings=[],trace=dict(observations=obs,raw_pointers=pointers,validations=checks)))
    chains=[dict(chain_id=identity('sch',1),stage_ids=ids,relation_ids=[d['candidate_id'] for d in decisions],single_stage=count==1,
        entry_stage_ids=[ids[0]],exit_stage_ids=[ids[-1]],entry_exit_basis='existing_directed_relations_only',weak_direction_is_causal=False,
        has_directed_cycle=False,start_time='2026-01-01T00:00:00Z',end_time='2026-01-01T00:00:00Z')]
    n=dict(contract_version=VERSIONS['chains'],input_digest='5'*64,chains=chains,guard={})
    schema=json.loads((ROOT/'docs/attack_step_output.schema.json').read_text('utf8'))
    s=Snapshot(source,n,{},dict(dataset_version='SYNTHETIC_TEST_ONLY'),dict.fromkeys(['dataset','stage8','stage9','receipt','provenance','schema'],'6'*64),schema,'7'*64)
    build_indexes(s)
    refresh(s)
    return s

def refresh(s):
    build_indexes(s)
    s.indexes['accepted']={k:d for k,d in s.indexes['relation_decision'].items() if d['relation_type']!='NO_RELATION'}
    s.indexes['chain_owner']={sid:ch['chain_id'] for ch in s.stage9['chains'] for sid in ch['stage_ids']}
    s.indexes['stage_owner']={a:st['stage_id'] for st in s.stage8['stages']['stages'] for a in st['alert_ids']}
    # Same signature used by the formal artifact. This is fixture serialization,
    # not execution of Stage/Relation/Chain reconstruction.
    payload=dict(stages=dict(sorted(s.indexes['stage'].items())),relations=dict(sorted(s.indexes['accepted'].items())),
        decisions=s.stage8['evidence']['decisions'],evidence=s.stage8['evidence'],alerts=dict(sorted(s.indexes['alert'].items())),legacy_input=None)
    s.stage9['input_digest']=content_digest(payload)
    s.receipt['graph_input_digest']=s.stage9['input_digest']
    s.original_signature=signature(s)

def evaluate_all(s,kind=None):
    return evaluate(s,Proposal(tuple(sorted(s.indexes['stage'])),('SYNTHETIC_TEST',),kind),run_id(envelope(s)))

def no_relations(s):
    for d in s.stage8['evidence']['decisions']:
        d.update(relation_type='NO_RELATION',direction_claim='NONE',from_stage_id=None,to_stage_id=None,primary_claim_id=None,relation_claim_ids=[],context_claim_ids=[])
    for ch in s.stage9['chains']: ch['relation_ids']=[]
    refresh(s)

def fixture_files(s,tmp_path):
    folder=tmp_path/'inputs'; folder.mkdir()
    for name,value in [('stage8',s.stage8),('stage9',s.stage9)]:
        (folder/(name+'.json')).write_text(json.dumps(value),encoding='utf8')
    (folder/'dataset.jsonl').write_text('{}\n',encoding='utf8')
    provenance=dict(contract_version='attack-step-provenance-v1.1',dataset_version='SYNTHETIC_TEST_ONLY',
        dataset_sha256=sha((folder/'dataset.jsonl').read_bytes()),producer='synthetic tests',
        version_source=dict(kind='PRODUCER_RELEASE',reference='synthetic release receipt'))
    (folder/'provenance.json').write_text(json.dumps(provenance),encoding='utf8')
    receipt=dict(input_sha256=provenance['dataset_sha256'],relation_id_field='candidate_id',
        stage8_sha256=sha((folder/'stage8.json').read_bytes()),stage9_sha256=sha((folder/'stage9.json').read_bytes()),
        graph_input_digest=s.stage9['input_digest'])
    (folder/'receipt.json').write_text(json.dumps(receipt),encoding='utf8')
    files={k:folder/(k+'.json') for k in ['stage8','stage9','receipt','provenance']}; files['dataset']=folder/'dataset.jsonl'
    files.update(contract=ROOT/'docs/ATTACK_STEP_SEMANTIC_CONTRACT.md',schema=ROOT/'docs/attack_step_output.schema.json',
        freeze_manifest=ROOT/'outputs/attack_step_contract_freeze_20261022/documentation_manifest.json')
    return files

def test_complete_p1_confirms_and_traces():
    s=synthetic(); g,l=evaluate_all(s)
    assert g['membership_status']=='CONFIRMED'
    assert g['grouping_basis']['purpose_rule_id']==P1
    assert g['purpose_covered_alert_ids']==sorted(s.indexes['alert'])
    assert g['member_stage_ids']==sorted(s.indexes['stage'])
    assert all(checked_reference(s,r)['resolution']=='RESOLVED' for r in g['evidence_refs'])

def test_different_actions_parent_child_only_candidate():
    g,l=evaluate_all(synthetic(p1=False))
    assert g['membership_status']=='CANDIDATE' and g['evidence_level']=='E2'

def test_unknown_singleton():
    s=synthetic(count=1); g,l=evaluate_all(s)
    assert g['membership_status']=='UNRESOLVED' and not g['source_relation_ids']

@pytest.mark.parametrize('basis',['host','time','session','label','community'])
def test_shared_context_cannot_confirm(basis):
    s=synthetic(p1=False); no_relations(s)
    if basis=='host':
        for st in s.stage8['stages']['stages']: st['host_entities']=[identity('ent',1)]
    if basis=='session':
        for st in s.stage8['stages']['stages']: st['session_bindings']=['session:shared']
    if basis=='label':
        for st in s.stage8['stages']['stages']: st['behavior']='NETWORK_ACTIVITY'
    refresh(s); g,l=evaluate_all(s)
    assert g['membership_status']=='UNRESOLVED'

def test_accepted_undirected_stays_undirected(tmp_path):
    s=synthetic(p1=False); d=s.stage8['evidence']['decisions'][0]
    d.update(relation_type='UNDIRECTED_EDGE',direction_claim='UNDIRECTED',from_stage_id=None,to_stage_id=None)
    refresh(s); loaded=load_inputs(fixture_files(s,tmp_path)); output,*_=compute(loaded)
    p=output['projected_relation_view'][0]
    assert p['relation_type']=='UNDIRECTED_EDGE' and p['from_stage_id'] is None
    assert not any(g['membership_status']=='CONFIRMED' for g in output['semantic_groups'])

def test_rejected_relation_not_projected(tmp_path):
    s=synthetic(p1=False); no_relations(s)
    loaded=load_inputs(fixture_files(s,tmp_path)); output,_,ledger,_=compute(loaded)
    assert output['projected_relation_view']==[]
    assert all(not g['source_relation_ids'] for g in output['semantic_groups'])
    assert any(l['negative_evidence'] for l in ledger)
    rejected=set(loaded.indexes['relation_decision'])
    assert not any(r['kind']=='relation_decision' and r['target_id'] in rejected for l in ledger for r in l['positive_evidence'])

def test_typed_request_binding_without_relation_not_confirmed():
    s=synthetic(); no_relations(s); g,l=evaluate_all(s,'request')
    assert g['membership_status']=='UNRESOLVED'

def test_explicit_identity_conflict_rejected():
    s=synthetic(); s.stage8['alerts'][1]['contexts'][0]['value']='different'
    s.stage8['alerts'][1]['raw_alert']['request_id']='different'; refresh(s)
    g,l=evaluate_all(s,'request')
    assert g['membership_status']=='REJECTED' and g['contradictions']

def test_group_expansion_checks_nonadjacent_conflict():
    s=synthetic(count=3); s.stage8['alerts'][2]['contexts'][0]['value']='different'
    s.stage8['alerts'][2]['raw_alert']['request_id']='different'; refresh(s)
    pair=Proposal(tuple(sorted(s.indexes['stage'])[:2]),('TEST',),'request')
    assert evaluate(s,pair,run_id(envelope(s)))[0]['membership_status']=='CONFIRMED'
    g,l=evaluate_all(s,'request')
    assert g['membership_status']=='REJECTED'
    assert len(l['whole_group_check']['pair_checks'])==3

def test_group_partial_coverage_never_confirms():
    s=synthetic(); extra=copy.deepcopy(s.stage8['alerts'][0]); extra['alert_id']=identity('alt',99)
    s.stage8['alerts'].append(extra)
    st=s.stage8['stages']['stages'][0]; st['alert_ids'].append(extra['alert_id']); st['alert_count']+=1
    s.stage8['stages']['behaviors'].append(dict(alert_id=extra['alert_id'],behavior='UNKNOWN',evidence=[]))
    refresh(s); g,l=evaluate_all(s)
    assert g['membership_status']=='UNRESOLVED' and extra['alert_id'] in l['whole_group_check']['p1']['uncovered_alert_ids']

@pytest.mark.parametrize('damage',['raw_pointer','witness','binding','roles','authority','temporal','validation','null'])
def test_p1_missing_or_invalid_evidence(damage):
    s=synthetic(); c=s.stage8['evidence']['claims'][0]
    if damage=='raw_pointer': s.stage8['evidence']['trace']['raw_pointers'][0]['raw_pointer']['pointer']='/absent'
    elif damage=='witness': s.stage8['evidence']['trace']['observations'][0]['alert_a_id']=identity('alt',99)
    elif damage=='binding': s.stage8['alerts'][0]['contexts']=[]
    elif damage=='roles': c['role_a']='RESPONSE'
    elif damage=='authority': c['identity']['scope']='{}'; c['metadata']['projection_identity']['scope']='{}'
    elif damage=='temporal': s.stage8['evidence']['trace']['validations'][0]['temporal_check']['status']='CONFLICT'
    elif damage=='validation': s.stage8['evidence']['trace']['validations'][0]['valid']=False
    else: s.stage8['alerts'][0]['raw_alert']['request_id']=None
    refresh(s)
    try: proof=p1_proof(s,sorted(s.indexes['stage']))
    except (KeyError,PrototypeError): return
    assert not proof['complete']

def test_dangling_reference_is_detected():
    s=synthetic(); r=reference('claim',identity('ecl',999))
    assert checked_reference(s,r)['resolution']=='MISSING'

def test_existing_root_pointer_and_escaped_pointer():
    from app.attack_steps.loader import pointer
    s=synthetic(); aid=next(iter(s.indexes['alert']))
    raw=s.indexes['alert'][aid]['raw_alert']; raw['a/b~c']={'value':7}
    assert pointer(s,dict(alert_id=aid,pointer='',side='shared')) is raw
    assert pointer(s,dict(alert_id=aid,pointer='/a~1b~0c/value',side='shared'))==7

def test_duplicate_stage_in_proposal_fails():
    s=synthetic(); sid=next(iter(s.indexes['stage']))
    with pytest.raises(PrototypeError): evaluate(s,Proposal((sid,sid),('BAD',)),run_id(envelope(s)))

def test_competing_confirmed_groups_all_downgraded():
    s=synthetic(count=3); ids=sorted(s.indexes['stage']); r=run_id(envelope(s))
    groups,ledger=build_groups(s,[Proposal(tuple(ids[:2]),('PAIR',)),Proposal(tuple(ids[1:]),('PAIR',)),Proposal(tuple(ids),('GROUP',))],r)
    assert all(g['membership_status']!='CONFIRMED' for g in groups)
    assert all(l['decision_reason']=='PRIMARY_MEMBERSHIP_CONFLICT' for l in ledger)

def test_same_chain_induced_subset_disconnected():
    s=synthetic(count=3); ids=sorted(s.indexes['stage'])
    assert components(s,[ids[0],ids[2]])==[[ids[0]],[ids[2]]]

def test_cross_chain_candidate_preserves_disconnection():
    s=synthetic(p1=False); no_relations(s); ids=sorted(s.indexes['stage'])
    for st,al in zip(s.stage8['stages']['stages'],s.stage8['alerts'],strict=True):
        st['flow_bindings']=['flow:shared']; al.update(url='/observed',alert_type='alert')
    first=s.stage9['chains'][0]; first.update(stage_ids=[ids[0]],single_stage=True)
    second=copy.deepcopy(first); second.update(chain_id=identity('sch',2),stage_ids=[ids[1]])
    s.stage9['chains'].append(second); refresh(s)
    g,l=evaluate_all(s)
    assert g['membership_status']=='CANDIDATE' and g['disconnected_members']
    assert len(g['member_chain_ids'])==2 and not g['source_relation_ids']

def test_loader_reads_real_fields_and_descriptors(tmp_path):
    files=fixture_files(synthetic(),tmp_path); s=load_inputs(files); view=descriptors(s)
    assert len(s.indexes['stage'])==2 and len(s.indexes['accepted'])==1 and len(s.indexes['chain'])==1
    assert len(view)==2 and view[0]['member_alert_ids'] and 'process_lineage' in view[0]

def test_descriptor_method_pointer_and_session_types():
    from app.attack_steps.loader import pointer
    s=synthetic(); s.stage8['alerts'][0]['raw_alert']['method']='POST'
    for st in s.stage8['stages']['stages']: st['session_bindings']=['session:mixed-type-key']
    refresh(s); view=descriptors(s)
    item=view[0]['url_method'][0]['method_observations'][0]
    assert item['pointer']=='/method'
    assert pointer(s,dict(alert_id=view[0]['member_alert_ids'][0],pointer=item['pointer'],side='shared'))=='POST'
    assert view[0]['session_bindings'] and not view[0]['network_session']

@pytest.mark.parametrize('failure',['sha','required_field','duplicate_stage','missing_witness','version','provenance','duplicate_key'])
def test_loader_fail_closed(tmp_path,failure):
    s=synthetic()
    if failure=='required_field': del s.stage8['stages']['stages'][0]['alert_ids']
    if failure=='duplicate_stage': s.stage8['stages']['stages'].append(copy.deepcopy(s.stage8['stages']['stages'][0]))
    if failure=='missing_witness': s.stage8['evidence']['trace']['observations'][0]['alert_a_id']=identity('alt',999)
    if failure=='version': s.stage8['evidence']['contract_version']='unknown'
    files=fixture_files(s,tmp_path)
    if failure=='sha': files['stage8'].write_text('{}',encoding='utf8')
    if failure=='provenance': files['provenance'].write_text('{}',encoding='utf8')
    if failure=='duplicate_key': files['provenance'].write_text('{"contract_version":"a","contract_version":"b"}',encoding='utf8')
    with pytest.raises((PrototypeError,KeyError)): load_inputs(files)

def test_firewall_blocks_arbitrary_read_and_write(tmp_path):
    allowed=tmp_path/'input.json'; allowed.write_text('{}',encoding='utf8'); outside=tmp_path/'ground_truth.json'; outside.write_text('{}',encoding='utf8')
    out=tmp_path/'out'; out.mkdir()
    with ReadOnlyGuard([allowed],out) as g:
        assert allowed.read_text()=='{}'
        with pytest.raises(PermissionError): outside.read_text()
        with pytest.raises(PermissionError): allowed.write_text('changed')
        (out/'new.json').write_text('{}')
    assert sum(e.get('allowed') is False for e in g.events)==2

def test_firewall_blocks_network_and_subprocess(tmp_path):
    import socket,subprocess
    out=tmp_path/'out'; out.mkdir()
    with ReadOnlyGuard([],out):
        with pytest.raises(PermissionError): socket.socket()
        with pytest.raises(PermissionError): subprocess.run([sys.executable,'-V'])

def test_two_complete_runs_stable_and_sealed(tmp_path):
    files=fixture_files(synthetic(),tmp_path); before=file_digests(files)
    a=execute(files,tmp_path/'run1'); b=execute(files,tmp_path/'run2')
    assert a==b and file_digests(files)==before
    assert (tmp_path/'run1/attack_step_semantic_output.json').read_bytes()==(tmp_path/'run2/attack_step_semantic_output.json').read_bytes()
    assert json.loads((tmp_path/'run1/seal.json').read_text())['sha256']==sha((tmp_path/'run1/attack_step_semantic_output.json').read_bytes())
    with pytest.raises(PrototypeError): execute(files,tmp_path/'run1')

def test_fresh_cli_process(tmp_path):
    import subprocess
    files=fixture_files(synthetic(),tmp_path)
    command=[sys.executable,str(ROOT/'scripts/run_attack_step_prototype.py')]
    for k in ['stage8','stage9','receipt','dataset','provenance']: command.extend(['--'+k,str(files[k])])
    command.extend(['--output',str(tmp_path/'fresh_run')])
    env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}
    env.pop('TRACEBACK_SCHEMA_VALIDATOR_PATH', None)
    result=subprocess.run(command,capture_output=True,text=True,env=env)
    assert result.returncode==0,result.stderr
    assert (tmp_path/'fresh_run/seal.json').is_file()

def test_iteration_order_does_not_change_result(tmp_path):
    s=load_inputs(fixture_files(synthetic(),tmp_path)); a=compute(s)[0]
    for k in list(s.indexes):
        if isinstance(s.indexes[k],dict): s.indexes[k]=dict(reversed(list(s.indexes[k].items())))
    b=compute(s)[0]
    assert a==b

@pytest.mark.parametrize('mutation',['new_edge','reverse','missing_stage','wrong_group_id','false_trace','duplicate_membership','dangling','lost_decision','overlap','missing_pair_check'])
def test_validation_rejects_forged_output(tmp_path,mutation):
    s=load_inputs(fixture_files(synthetic(),tmp_path)); output,_,ledger,_=compute(s)
    if mutation=='new_edge': output['projected_relation_view'].append(copy.deepcopy(output['projected_relation_view'][0]))
    elif mutation=='reverse': output['projected_relation_view'][0]['direction_claim']='B_TO_A'
    elif mutation=='missing_stage': output['stage_membership_index'].pop()
    elif mutation=='wrong_group_id': output['semantic_groups'][0]['semantic_step_id']=identity('asp',999)
    elif mutation=='false_trace': output['evidence_trace_summary']['resolved_reference_occurrences']+=1
    elif mutation=='duplicate_membership': output['stage_membership_index'].append(copy.deepcopy(output['stage_membership_index'][0]))
    elif mutation=='dangling': next(g for g in output['semantic_groups'] if g['membership_status']=='CONFIRMED')['evidence_refs'][0]['target_id']=identity('ecl',999)
    elif mutation=='lost_decision': output['decision_ledger'].pop()
    elif mutation=='missing_pair_check': next(l for l in ledger if len(l['member_stage_ids'])==2)['whole_group_check']['pair_checks']=[]
    else:
        row=copy.deepcopy(next(g for g in output['semantic_groups'] if g['membership_status']=='CONFIRMED'))
        row['semantic_step_id']=identity('asp',888); output['semantic_groups'].append(row)
    with pytest.raises((PrototypeError,KeyError)): validate(s,output,ledger)

def test_source_object_mutation_fails(tmp_path):
    s=load_inputs(fixture_files(synthetic(),tmp_path)); s.stage9['chains'][0]['stage_ids'].pop()
    with pytest.raises(PrototypeError): compute(s)

def test_jcs_utf16_and_non_normalization():
    assert jcs({'\U0001f600':1,'\ue000':2})=='{"😀":1,"":2}'
    assert jcs('e\u0301')!='"é"'
    with pytest.raises(PrototypeError): jcs(0.1)
