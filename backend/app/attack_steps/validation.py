"""Schema and independent source/reference/integrity checks V01--V12."""
from collections import Counter
from itertools import combinations
from jsonschema import Draft202012Validator

from .evidence import checked_reference,resolve,p1_proof,identity_contradictions,partition_evidence
from .grouping import components
from .loader import file_digests,signature
from .models import P1,VERSION,TAXONOMY,VERSIONS,group_id,index,require,run_id,unique
from .projection import membership_index,project

def envelope(s):
    return dict(contract_version=VERSION,taxonomy_version=TAXONOMY,dataset_version=s.provenance['dataset_version'],
        input_artifact_digests={key+'_sha256':s.digests[name] for key,name in [
            ('dataset','dataset'),('stage8','stage8'),('stage9','stage9'),('receipt','receipt'),('provenance_receipt','provenance')]},
        upstream_config_digests={key:s.stage8[field]['config_hash'] for key,field in [
            ('community','communities'),('stages','stages'),('candidates','candidates'),('evidence','evidence')]},
        upstream_contract_versions=dict(VERSIONS),graph_input_digest=s.stage9['input_digest'],policy_digest=s.policy_digest)

def all_references(output):
    for g in output['semantic_groups']:
        yield from g['evidence_refs']
        for c in g['contradictions']: yield from c['evidence_refs']
    for d in output['decision_ledger']: yield from d['evidence_refs']

def trace_summary(s,output):
    total=resolved=0; alerts=set(); locations=set(); missing=[]
    for ref in all_references(output):
        total+=1; actual=checked_reference(s,ref)
        if actual['resolution']=='RESOLVED':
            aa,pp=resolve(s,ref); alerts.update(aa); locations.update(pp); resolved+=1
        else:
            missing.append(dict(evidence_ref=actual,reason='Source lookup returned '+actual['resolution']))
    confirmed=[g for g in output['semantic_groups'] if g['membership_status']=='CONFIRMED']
    complete=sum(p1_proof(s,g['member_stage_ids'])['complete'] and
                 all(checked_reference(s,r)['resolution']=='RESOLVED' for r in g['evidence_refs']) for g in confirmed)
    return dict(reference_occurrences=total,resolved_reference_occurrences=resolved,
        unique_alert_count=len(alerts),unique_raw_pointer_count=len(locations),
        confirmed_group_count=len(confirmed),confirmed_groups_with_complete_evidence=complete,
        unresolved_refs=unique(missing))

def integrity_summary(s,output):
    require(signature(s)==s.original_signature,'source_snapshot_mutated')
    require(file_digests(s.files)==s.digests,'input_file_changed_during_run')
    counts=Counter(sid for g in output['semantic_groups'] if g['membership_status']=='CONFIRMED' for sid in g['member_stage_ids'])
    require(all(n==1 for n in counts.values()),'duplicate_primary_membership')
    return dict(input_digests_verified=True,original_stages_preserved=True,original_relations_preserved=True,
        original_chains_preserved=True,ground_truth_used_for_grouping=False,new_relation_count=0,reversed_relation_count=0,
        duplicate_primary_membership_count=0,source_stage_count=len(s.indexes['stage']),
        source_accepted_relation_count=len(s.indexes['accepted']),
        source_rejected_relation_count=len(s.indexes['relation_decision'])-len(s.indexes['accepted']),
        source_chain_count=len(s.indexes['chain']),
        unassigned_stage_count=sum(m['primary_semantic_step_id'] is None for m in output['stage_membership_index']),
        semantic_validation_status='PASSED_V01_V12')

def schema_validate(s,output):
    Draft202012Validator.check_schema(s.schema)
    errors=sorted(Draft202012Validator(s.schema).iter_errors(output),key=lambda e:str(e.absolute_path))
    require(not errors,'output_schema_invalid:'+'; '.join(e.message for e in errors[:3]))
    return dict(valid=True,draft='2020-12',validator='jsonschema',error_count=0,schema_sha256=s.digests['schema'])

def validate(s,output,candidate_ledger):
    schema=schema_validate(s,output)
    expected=envelope(s)
    require(all(output.get(k)==v for k,v in expected.items()),'V01_envelope_mismatch')
    require(output['run_id']==run_id(output),'V01_run_identity_mismatch')
    groups=index(output['semantic_groups'],'semantic_step_id')
    ledgers=index(output['decision_ledger'],'semantic_step_id')
    detailed=index(candidate_ledger,'candidate_id')
    require(set(groups)==set(ledgers)==set(detailed),'V11_decision_ledger_incomplete')
    stages=s.indexes['stage']; accepted=s.indexes['accepted']
    for key,g in groups.items():
        members=g['member_stage_ids']; member_set=set(members)
        require(members==sorted(member_set) and member_set<=stages.keys(),'V03_invalid_group_members')
        require(key==group_id(output['run_id'],members,g['semantic_label'],g['grouping_basis']['purpose_rule_id']),'V01_group_identity_mismatch')
        require(g['member_chain_ids']==sorted({s.indexes['chain_owner'][sid] for sid in members}),'V03_chain_membership_mismatch')
        source_ids=sorted(rid for rid,d in accepted.items() if {d['stage_a_id'],d['stage_b_id']}<=member_set)
        require(g['source_relation_ids']==source_ids,'V05_source_relations_mismatch')
        alerts={a for sid in members for a in stages[sid]['alert_ids']}
        require(set(g['supporting_alert_ids'])<=alerts,'V06_supporting_alert_outside_members')
        require(g['connected_components']==components(s,members),'V08_induced_partition_mismatch')
        require(g['disconnected_members']==(len(g['connected_components'])>1),'V08_disconnection_mismatch')
        for ref in g['evidence_refs']:
            require(checked_reference(s,ref)['resolution']==ref['resolution'],'V06_false_reference_resolution')
        proof=p1_proof(s,members)
        require(g['purpose_covered_alert_ids']==proof['covered_alert_ids'],'V07_purpose_coverage_mismatch')
        if g['membership_status']=='CONFIRMED':
            require(proof['complete'] and set(g['purpose_covered_alert_ids'])==alerts,'V07_incomplete_confirmation_proof')
            require(len(g['member_chain_ids'])==1 and not g['disconnected_members'],'V08_disconnected_confirmation')
            require(not g['contradictions'] and not g['unresolved_questions'],'V07_confirmation_with_uncertainty')
            require(all(r['resolution']=='RESOLVED' for r in g['evidence_refs']),'V07_dangling_confirmation')
            require(set(proof['claim_ids']) <= {r.get('target_id') for r in g['evidence_refs'] if r['kind']=='claim'},'V07_purpose_claim_not_cited')
        if g['membership_status']=='REJECTED':
            kind=detailed[key]['whole_group_check']['identity_hypothesis']
            require(g['contradictions']==identity_contradictions(s,members,kind) and g['contradictions'],'V11_unsubstantiated_rejection')
        d=ledgers[key]; l=detailed[key]
        require(d['status']==g['membership_status']==l['decision'],'V11_status_mismatch')
        require(d['reason_codes']==g['grouping_basis']['reason_codes']==[l['decision_reason']],'V11_reason_mismatch')
        require(d['evidence_refs']==g['evidence_refs'] and l['evidence_items']==g['evidence_refs'],'V11_evidence_mismatch')
        positive,negative=partition_evidence(s,g['evidence_refs'],g['contradictions'])
        require(l['positive_evidence']==positive and l['negative_evidence']==negative,'V11_evidence_polarity_mismatch')
        require(l['member_stage_ids']==members and l['whole_group_check']['all_pairs_checked'],'V11_member_check_mismatch')
        require([(p['stage_a_id'],p['stage_b_id']) for p in l['whole_group_check']['pair_checks']]==list(combinations(members,2)),'V11_pair_check_incomplete')
        expected_decisions=sorted(rid for rid,row in s.indexes['relation_decision'].items() if {row['stage_a_id'],row['stage_b_id']}<=member_set)
        require(d['source_decision_ids']==l['source_decision_ids']==expected_decisions,'V11_original_decision_loss')
        for contradiction in g['contradictions']:
            require(all(checked_reference(s,r)['resolution']=='RESOLVED' for r in contradiction['evidence_refs']),'V11_unresolved_contradiction')
    index(output['stage_membership_index'],'stage_id')
    require(output['stage_membership_index']==membership_index(s,list(groups.values())),'V02_V04_membership_index_mismatch')
    index(output['projected_relation_view'],'source_relation_id')
    require(output['projected_relation_view']==project(s,output['stage_membership_index']),'V09_V10_relation_projection_mismatch')
    recomputed=trace_summary(s,output)
    require(recomputed==output['evidence_trace_summary'],'V12_trace_count_mismatch')
    require(recomputed['confirmed_groups_with_complete_evidence']==recomputed['confirmed_group_count'],'V07_confirmed_trace_incomplete')
    require(output['integrity_summary']==integrity_summary(s,output),'V12_integrity_mismatch')
    return dict(schema=schema,checks={f'V{n:02d}':'PASS' for n in range(1,13)},
        confirmed_group_count=recomputed['confirmed_group_count'],
        confirmed_group_evidence_trace_success=recomputed['confirmed_groups_with_complete_evidence'],
        confirmed_group_dangling_reference_count=0,
        reference_occurrences=recomputed['reference_occurrences'],resolved_reference_occurrences=recomputed['resolved_reference_occurrences'])

