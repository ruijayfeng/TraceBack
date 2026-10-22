"""Whole-proposal evidence checks. Connectivity alone never groups Stages."""
from collections import Counter
from itertools import combinations
from .evidence import (claim_is_valid,evidence_refs,identity_contradictions,p1_proof,partition_evidence)
from .membership import (boundary_breaches,common_membership_anchors)
from .models import P1, group_id, require, unique

def components(s,members):
    adjacency={sid:set() for sid in members}
    for d in s.indexes['accepted'].values():
        a,b=d['stage_a_id'],d['stage_b_id']
        if a in adjacency and b in adjacency:
            adjacency[a].add(b); adjacency[b].add(a)
    pending=set(members); result=[]
    while pending:
        frontier=[min(pending)]; found=set()
        while frontier:
            sid=frontier.pop()
            if sid in found: continue
            found.add(sid); frontier.extend(sorted(adjacency[sid]-found))
        pending-=found; result.append(sorted(found))
    return sorted(result)

def context(s,members):
    stages=[s.indexes['stage'][sid] for sid in members]
    shared={}
    for key in ['host_entities','account_entities','flow_bindings','session_bindings','request_bindings','task_bindings']:
        values=set(stages[0][key])
        for st in stages[1:]: values &= set(st[key])
        shared[key]=sorted(values)
    shared['community']=len({st['community_id'] for st in stages})==1
    shared['time_overlap']=max(st['start_time'] for st in stages)<=min(st['end_time'] for st in stages)
    return shared

def bounded_description(s,members,has_direct,shared):
    alerts=[[s.indexes['alert'][a] for a in s.indexes['stage'][sid]['alert_ids']] for sid in members]
    flat=[a for rows in alerts for a in rows]
    # Candidate descriptions only: no command parser, success inference or
    # credential identity claim. Literal file location + observed SSH transport
    # is a hypothesis; it can never satisfy P1.
    credential_file=any(isinstance(a.get('file'),str) and '/.ssh/' in a['file'].replace('\\','/') for a in flat)
    ssh_transport=any(a.get('dst_port')==22 for a in flat)
    if has_direct and credential_file and ssh_transport:
        return 'CREDENTIAL_ACTIVITY_CANDIDATE',True
    execution=any(s.indexes['stage'][sid]['behavior'] in {'EXECUTION','FILE_ACTIVITY'} for sid in members)
    if has_direct and execution and any(s.indexes['stage'][sid]['request_bindings'] for sid in members):
        return 'REQUEST_EXECUTION_CANDIDATE',True
    # A shared typed flow plus observed web detector activity supplies a bounded
    # Web candidate, not proof that different requests have one purpose.
    web=all(any(a.get('url') and (a.get('alert_type')=='alert' or a.get('category')=='web_attack') for a in rows) for rows in alerts)
    if len(members)>1 and shared['flow_bindings'] and web:
        return 'WEB_ACTIVITY_CANDIDATE',True
    if has_direct: return 'HOST_ACTIVITY_CANDIDATE',True
    return 'UNCLASSIFIED_ACTIVITY',False

def evaluate(s,proposal,run):
    members=list(proposal.members); member_set=set(members); i=s.indexes
    require(members==sorted(member_set) and member_set<=i['stage'].keys() and members,'invalid_proposal_members')
    direct=[d for d in i['accepted'].values() if {d['stage_a_id'],d['stage_b_id']}<=member_set]
    source_relations=sorted(d['candidate_id'] for d in direct)
    source_decisions=sorted(d['candidate_id'] for d in i['relation_decision'].values() if {d['stage_a_id'],d['stage_b_id']}<=member_set)
    refs=evidence_refs(s,members); missing=[r for r in refs if r['resolution']!='RESOLVED']
    proof=p1_proof(s,members); comp=components(s,members); shared=context(s,members)
    chains=sorted({i['chain_owner'][sid] for sid in members})
    valid_direct=any(any(claim_is_valid(s,i['claim'][cid]) for cid in d['relation_claim_ids']) for d in direct)
    level=('E1' if proof['claim_ids'] else 'E2' if valid_direct else 'E3' if
           any(shared[k] for k in shared) else 'E4' if len({i['stage'][sid]['behavior'] for sid in members})==1 else 'NONE')
    label,finite=bounded_description(s,members,valid_direct,shared)
    rule='NONE'; label_source='UNCLASSIFIED' if label=='UNCLASSIFIED_ACTIVITY' else 'EVIDENCE_BOUNDED_DESCRIPTION'
    if proposal.identity_kind=='request' or proof['claim_ids']:
        label='REQUEST_RESPONSE_TRANSACTION'; label_source='FROZEN_RULE'; rule=P1
    contradictions=identity_contradictions(s,members,proposal.identity_kind)
    # MEMBERSHIP_EVIDENCE_MODEL / STEP_BOUNDARY_MODEL (recorded for every status).
    anchors=common_membership_anchors(s,members)
    breaches,boundary_detail=boundary_breaches(s,members,proposal.identity_kind)
    membership_detail=dict(membership_anchor_keys=anchors,
        identity_kind=proposal.identity_kind,
        identity_status=boundary_detail['match_kind'],
        boundary_breaches=breaches)
    questions=[]
    if contradictions:
        status='REJECTED'; reason='INCOMPATIBLE_ACTIVITY_IDENTITY'
    elif missing:
        status='UNRESOLVED'; reason='MISSING_REQUIRED_EVIDENCE'; questions=['Evidence references cannot all be resolved.']
    elif proof['complete'] and len(comp)==1 and len(chains)==1:
        status='CONFIRMED'; reason='P1_COMPLETE'
    elif proposal.identity_kind=='request' or proof['claim_ids']:
        status='UNRESOLVED'; reason='INCOMPLETE_MEMBER_COVERAGE'; questions=proof['failures'] or ['P1 connectivity/Chain requirement is not satisfied.']
    elif finite and len(members)>1 and level in {'E1','E2','E3'}:
        # STEP_BOUNDARY_MODEL gate: a multi-member Candidate must carry a
        # whole-group membership anchor. Relation evidence (valid accepted
        # relation, shared flow/session, host/account, temporal proximity,
        # lineage) alone can never certify one Attack Step.
        retainable = bool(anchors) and boundary_detail['match_kind'] != 'CONFLICT'
        if retainable:
            status='CANDIDATE'; reason=('CROSS_CHAIN_CONFIRMATION_UNSUPPORTED' if len(chains)>1 else
                                       'DISCONNECTED_INDUCED_SUBGRAPH' if len(comp)>1 else 'PURPOSE_NOT_PROVEN')
            questions=['A shared high-level purpose and whole-member coverage are not proven by an approved P1 profile.']
        else:
            # Relation evidence does not establish a common bounded Attack Step.
            status='UNRESOLVED'
            reason=('INCOMPATIBLE_ACTIVITY_IDENTITY' if boundary_detail['match_kind']=='CONFLICT'
                    else 'RELATION_NOT_PURPOSE')
            questions=['Relation evidence does not establish a common bounded Attack Step; '
                       'no whole-group membership anchor is present.']
    else:
        status='UNRESOLVED'; reason=('REJECTED_RELATION_NOT_SUPPORT' if source_decisions and not direct else
            'CONTEXT_ONLY' if level=='E3' else 'SIMILARITY_ONLY' if level=='E4' else 'NO_ACCEPTED_CONNECTION')
        questions=['Existing observations do not establish one bounded high-level activity.']
    group=dict(semantic_step_id=group_id(run,members,label,rule),semantic_label=label,label_source=label_source,
        membership_status=status,member_stage_ids=members,member_chain_ids=chains,evidence_level=level,
        grouping_basis=dict(purpose_rule_id=rule,reason_codes=[reason],
            explanation='Readonly proposal evaluated against existing typed evidence; '+reason+'.'),
        source_relation_ids=source_relations,supporting_alert_ids=sorted({a for sid in members for a in i['stage'][sid]['alert_ids']}),
        purpose_covered_alert_ids=proof['covered_alert_ids'],evidence_refs=refs,contradictions=contradictions,
        unresolved_questions=questions,disconnected_members=len(comp)>1,connected_components=comp,
        limitations=['Semantic membership is not a causal edge or a continuous attack path.'] +
                    (['Members are disconnected in the original accepted induced graph.'] if len(comp)>1 else []))
    positive,negative=partition_evidence(s,refs,contradictions)
    ledger=dict(candidate_id=group['semantic_step_id'],member_stage_ids=members,
        candidate_generation_reason=list(proposal.reasons),positive_evidence=positive,
        evidence_items=refs,evidence_sources=sorted({r['kind'] for r in refs}),
        negative_evidence=negative,
        contradictions=contradictions,
        whole_group_check=dict(all_pairs_checked=True,action_differences_preserved=True,
            pair_checks=[dict(stage_a_id=a,stage_b_id=b,shared_context=context(s,[a,b]),
                behavior_values=[i['stage'][a]['behavior'],i['stage'][b]['behavior']],
                original_relation_ids=sorted(d['candidate_id'] for d in i['relation_decision'].values() if {d['stage_a_id'],d['stage_b_id']}=={a,b}),
                contradictions=identity_contradictions(s,[a,b],proposal.identity_kind)) for a,b in combinations(members,2)],
            shared_context=shared,induced_components=comp,p1=proof,
            unresolved_reference_count=len(missing),identity_hypothesis=proposal.identity_kind,
            membership_evidence=membership_detail),
        decision=status,decision_reason=reason,evidence_level=level,source_relation_ids=source_relations,
        source_decision_ids=source_decisions,supporting_alert_ids=group['supporting_alert_ids'])
    return group,ledger

def reference_for_decision(rid):
    return dict(artifact='stage8',kind='relation_decision',target_id=rid,resolution='RESOLVED')

def build_groups(s,proposals,run):
    groups={}; ledgers={}
    for p in proposals:
        g,l=evaluate(s,p,run); key=g['semantic_step_id']
        if key in groups:
            # Same final proposal identity from different retrieval origins.
            ledgers[key]['candidate_generation_reason']=sorted(set(ledgers[key]['candidate_generation_reason']+l['candidate_generation_reason']))
        else: groups[key]=g; ledgers[key]=l
    counts=Counter(sid for g in groups.values() if g['membership_status']=='CONFIRMED' for sid in g['member_stage_ids'])
    for key,g in groups.items():
        if g['membership_status']=='CONFIRMED' and any(counts[sid]>1 for sid in g['member_stage_ids']):
            g['membership_status']='UNRESOLVED'; g['unresolved_questions']=['Competing complete proposals share an original Stage.']
            g['grouping_basis']['reason_codes']=['PRIMARY_MEMBERSHIP_CONFLICT']
            g['grouping_basis']['explanation']='All conflicting proposals are unresolved; no arbitrary winner.'
            ledgers[key]['decision']='UNRESOLVED'; ledgers[key]['decision_reason']='PRIMARY_MEMBERSHIP_CONFLICT'
    return [groups[k] for k in sorted(groups)],[ledgers[k] for k in sorted(ledgers)]

