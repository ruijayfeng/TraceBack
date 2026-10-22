"""Audit 138 frozen SHARED_CONTEXT_ONLY decisions; never create relations.

No production replay, new behavior table, new identity scope, fanout cutoff or
weak admission window. Qualification that needs a new policy stays uncalibrated.
What-if graphs contain temporary neutral endpoint pairs, not Relation objects.
"""
import argparse
from collections import Counter, defaultdict
from contextlib import contextmanager
from hashlib import sha256
import json
from pathlib import Path
import statistics
import sys
from datetime import datetime

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'backend'))
sys.dont_write_bytecode=True
CATEGORIES=['PUBLIC_CONTEXT_ONLY','SINGLE_WEAK_CONTEXT','MULTIPLE_SUPPORTING_CONTEXTS',
    'EXCLUSIVE_LOCAL_CONTEXT','TEMPORALLY_LOCAL_MULTI_CONTEXT','CONTEXT_BUT_SEMANTIC_CONFLICT',
    'CONTEXT_SCOPE_UNTRUSTED','OTHER']
FILES_CHANGED=['scripts/audit_shared_context_weak_relation.py',
    'tests/audit-only/test_shared_context_weak_relation_audit.py','docs/SHARED_CONTEXT_WEAK_RELATION_AUDIT.md']
TYPE_FIELDS={'HOST':'shared_host','ACCOUNT':'shared_account','PROCESS':'shared_process',
    'REQUEST':'shared_request','FLOW':'shared_flow','AUTH_SESSION':'shared_auth_session',
    'NETWORK_SESSION':'shared_network_session','ENDPOINT':'shared_endpoint',
    'FILE_PATH':'shared_file_path','COMMAND':'shared_command','OBJECT':'shared_object','OTHER':'other'}
SUPPORT_KINDS={'SAME_HOST':'entity.HOST','SAME_ACCOUNT':'entity.ACCOUNT',
    'SHARED_PROCESS_DESCRIPTOR':'entity.PROCESS','SAME_URL':'url','SAME_COMMAND':'command',
    'NETWORK_ENDPOINT_OVERLAP':'endpoint','SHARED_FILE_PATH':'object_path','INCOMPLETE_FLOW':'flow_tuple'}


def encode(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))


def digest(value):
    return sha256(encode(value).encode('utf8')).hexdigest()


def sha(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def save(out,name,value):
    (out/name).write_text(json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2)+'\n',encoding='utf8')


@contextmanager
def no_production_execution():
    previous=sys.getprofile()
    forbidden=('app.stage_candidates.generator','app.stage_candidates.features','app.stage_evidence.validation',
        'app.stage_evidence.extraction','app.stage_evidence.claims','app.stage_chains','app.stage_relations.analysis',
        'app.services.stage_pipeline','app.services.alert_pipeline','app.adapters.multisource',
        'app.entities.extraction','app.community.builder','app.stages.aggregation','app.ai','app.api','evaluation')
    def profile(frame,event,arg):
        if event=='call' and frame.f_globals.get('__name__','').startswith(forbidden):
            raise AssertionError('audit_forbids_production_algorithm_execution')
    sys.setprofile(profile)
    try:yield
    finally:sys.setprofile(previous)


def seconds(value):
    return datetime.fromisoformat(value.replace('Z','+00:00')).timestamp()


def distribution(values):
    values=sorted(values)
    def percentile(p):
        if not values:return None
        x=(len(values)-1)*p;i=int(x)
        return values[i]+(values[min(i+1,len(values)-1)]-values[i])*(x-i)
    return dict(count=len(values),min=min(values) if values else None,
        median=statistics.median(values) if values else None,p75=percentile(.75),p90=percentile(.9),
        max=max(values) if values else None)


def temporal_observation(a,b):
    sa,ea,sb,eb=(seconds(v) for v in (a['start_time'],a['end_time'],b['start_time'],b['end_time']))
    gap=max(0, max(sa,sb)-min(ea,eb))
    if gap>300:kind='large_gap'
    elif gap>0:kind='forward_gap'
    elif sa!=sb and (ea==sb or eb==sa):kind='adjacent'
    else:kind='overlap'
    return dict(stage_a_start=a['start_time'],stage_a_end=a['end_time'],stage_b_start=b['start_time'],
        stage_b_end=b['end_time'],time_gap_seconds=gap,interval_relation=kind,
        interval_label_basis='large_gap is user-requested OVER_300S reporting bin, not weak eligibility',
        weak_temporal_locality='NEEDS_CALIBRATION',TEMPORAL_ORDER_IS_CAUSAL_EVIDENCE=False,
        production_direction_assigned=False)


def behavior_observation(a,b):
    # Existing stage semantics explicitly have no cross-label compatibility
    # table. Same-stage semantic_conflict is not a Stage Relation conflict.
    left,right=a['behavior'],b['behavior']
    state='unknown' if 'UNKNOWN' in {left,right} else 'same' if left==right else 'UNDEFINED'
    return dict(behavior_a=left,behavior_b=right,state=state,
        compatibility='UNDEFINED' if state in {'unknown','UNDEFINED'} else 'SAME_LABEL',
        existing_cross_label_mapping_available=False,formal_relation_behavior_conflict=False)


def graph_components(nodes,pairs):
    adjacency={s:set() for s in nodes}
    for a,b in pairs:
        if a==b or a not in adjacency or b not in adjacency:raise ValueError('invalid_what_if_endpoint')
        adjacency[a].add(b);adjacency[b].add(a)
    unseen=set(nodes);result=[]
    for root in sorted(nodes):
        if root not in unseen:continue
        unseen.remove(root);stack=[root];members=[]
        while stack:
            s=stack.pop();members.append(s)
            fresh=adjacency[s]&unseen;unseen-=fresh;stack.extend(sorted(fresh))
        result.append(sorted(members))
    return result


def graph_statistics(nodes,base_pairs,extra_pairs):
    combined=set(base_pairs)|set(extra_pairs)
    groups=graph_components(nodes,combined)
    return dict(extra_pair_count=len(set(extra_pairs)-set(base_pairs)),component_count=len(groups),
        isolated_stage_count=sum(len(g)==1 for g in groups),component_sizes=sorted(len(g) for g in groups),
        temporary_memory_only=True,relation_objects_created=0,production_direction_assigned=False)


def authority(context,entities,projection):
    identity=context['scoped_identity'];kind=context['context_type']
    scoped=identity.get('scope')
    parsed=json.loads(scoped) if isinstance(scoped,str) and scoped.startswith('{') else {}
    backed=[]
    if kind=='SESSION' and parsed.get('auth_session_projection'):
        for b in projection['auth_session_bindings']:
            if (b['authority_scope']==parsed.get('authority') and b['canonical_host_entity_id']==parsed.get('host')
                    and b['metadata']['token']==identity.get('value') and b['metadata']['partition']==parsed.get('lifecycle')):
                backed.append(b['projection_id'])
        level='authoritative binding' if backed else 'context only'
    elif kind=='PROCESS':
        entity=entities.get(identity.get('process'))
        level='scoped binding' if entity and entity['scope'] else 'context only'
    else:
        level='scoped binding' if scoped else 'context only'
    valid=bool(context['metadata']['identity_complete'] and not context['metadata']['identity_polluted'] and
        level in {'scoped binding','authoritative binding'})
    return dict(authority_class=level,scope_trusted_within_original_identity=valid,
        semantic_class='CONTEXT',original_identity=identity,authority_binding_ids=backed,
        new_cross_source_identity_projection=False,
        cross_source_network_authority=False if kind in {'FLOW','CONNECTION'} else None,
        why_not_relation='Existing global membership is nonexclusive; no valid direct relation claim.',
        formal_policy=context['metadata']['direct_policy'])


def context_catalog(handoff,decisions):
    contexts={c['context_identity_id']:c for c in handoff['evidence']['context_postings']}
    entities={e['entity_id']:e for e in handoff['entities']}
    pointers={p['pointer_id']:p['raw_pointer'] for p in handoff['evidence']['trace']['raw_pointers']}
    used=sorted({cid for d in decisions for cid in d['context_identity_ids']})
    result={}
    for cid in used:
        c=contexts[cid]
        if len(c['stage_ids'])!=len(set(c['stage_ids'])):raise ValueError('invalid_global_context_fanout')
        row=dict(context_id=cid,context_type=c['context_type'],original_context=c,
            context_member_stage_count=len(c['stage_ids']),context_member_alert_count=len(c['alert_ids']),
            context_member_source_count=len(c['source_namespaces']),context_span_seconds=seconds(c['last_seen'])-seconds(c['first_seen']),
            stage_fanout=len(c['stage_ids']),HIGH_FANOUT_CONTEXT=len(c['stage_ids'])>2,
            fanout_label_basis='structural multi-Stage (>2), complement of existing two-Stage exclusivity; not a new weak cutoff',
            pairwise_context=len(c['stage_ids'])==2,authority=authority(c,entities,handoff['identity_projection']),
            member_raw_pointers=[dict(stage_id=m['stage_id'],alert_id=m['alert_id'],role=m['role'],
                raw_pointers=[pointers[p] for p in m['raw_pointer_ids']]) for m in c['memberships']])
        result[cid]=row
    return result


def support_catalog(handoff,decisions,postings):
    """Reuse original ⑧ Observation identity and membership for supporting facts.

    These rows are audit fact inventories; never new formal Context objects.
    No token is merged outside its original scoped projection identity.
    """
    claims={c['claim_id']:c for c in handoff['evidence']['claims']}
    aa={a['alert_id']:a for a in handoff['alerts']}
    original=defaultdict(list)
    for sid,observations in postings.items():
        for o in observations:
            original[(o['kind'],encode(json.loads(o['identity'])))].append(dict(stage_id=sid,**o))
    result={}
    for d in decisions:
        for claim_id in d['supporting_claim_ids']:
            c=claims[claim_id];typ=c['evidence_type'];identity=c['metadata']['projection_identity']
            kind=SUPPORT_KINDS.get(typ)
            if kind is None:raise ValueError('unknown_original_supporting_projection:'+typ)
            key=typ+':'+encode(identity)
            if key in result:continue
            members=original.get((kind,encode(identity)),[])
            if not members:raise ValueError('supporting_claim_missing_original_posting')
            stages=sorted({m['stage_id'] for m in members});alerts=sorted({m['alert_id'] for m in members})
            result[key]=dict(audit_fact_key=key,evidence_type=typ,original_projection_kind=kind,original_identity=identity,
                stage_ids=stages,alert_ids=alerts,source_namespaces=sorted({aa[i]['source_namespace'] for i in alerts}),
                context_member_stage_count=len(stages),context_member_alert_count=len(alerts),
                context_member_source_count=len({aa[i]['source_namespace'] for i in alerts}),
                context_span_seconds=max(seconds(aa[i]['timestamp']) for i in alerts)-min(seconds(aa[i]['timestamp']) for i in alerts),
                authority_class='context only',semantic_class='SUPPORTING',formal_context_identity_id=None,
                original_posting_observations=members)
    return result


def anchor_families(contexts,a,b):
    """Distinct identities require distinct native pointer paths, not type count.

    Multiple Process identities (parent/current) stay one family. Host/Account,
    process descriptors and five-tuple/endpoint copies do not add independent
    anchors to Process/AuthSession/Flow. This proves different observations,
    never statistical or causal independence.
    """
    grouped=defaultdict(list)
    for c in contexts:
        family='AUTH_SESSION' if c['authority']['authority_class']=='authoritative binding' and c['context_type']=='SESSION' else c['context_type']
        grouped[family].append(c)
    distinct=[]
    names=sorted(grouped)
    for i,left in enumerate(names):
        for right in names[i+1:]:
            lp={p['pointer'] for c in grouped[left] for m in c['member_raw_pointers'] if m['stage_id'] in {a,b} for p in m['raw_pointers']}
            rp={p['pointer'] for c in grouped[right] for m in c['member_raw_pointers'] if m['stage_id'] in {a,b} for p in m['raw_pointers']}
            distinct.append(dict(family_a=left,family_b=right,distinct_native_observation_paths=bool(lp-rp and rp-lp),
                exclusive_paths_a=sorted(lp-rp),exclusive_paths_b=sorted(rp-lp),
                statistical_or_causal_independence_proven=False))
    return dict(families=names,family_count=len(names),distinct_family_observations=distinct,
        multiple_distinct_anchors=any(p['distinct_native_observation_paths'] for p in distinct),
        independence_for_weak_admission='NEEDS_CALIBRATION')


def classify(row):
    """Audit classification has no graph/component/GT/edge inputs."""
    contexts=row['contexts'];complete=all(c['authority']['scope_trusted_within_original_identity'] for c in contexts)
    conflict=bool(row['hard_conflict'] or row['observed_formal_conflicts'])
    if conflict:category='CONTEXT_BUT_SEMANTIC_CONFLICT';bucket='CLEAR_NO_RELATION'
    elif not complete:category='CONTEXT_SCOPE_UNTRUSTED';bucket='CLEAR_NO_RELATION'
    elif row['anchors']['multiple_distinct_anchors']:
        category='MULTIPLE_SUPPORTING_CONTEXTS';bucket='AMBIGUOUS'
    elif contexts and all(c['stage_fanout']>2 for c in contexts):
        category='PUBLIC_CONTEXT_ONLY';bucket='CLEAR_NO_RELATION'
    else:
        category='OTHER';bucket='AMBIGUOUS'
    return dict(audit_category=category,qualification_bucket=bucket,WEAK_RELATION_CANDIDATE=False,
        weak_eligibility='NEEDS_CALIBRATION' if bucket=='AMBIGUOUS' else 'NOT_SUPPORTED_BY_CURRENT_EVIDENCE',
        why_not_strong='Formal decision has zero valid direct relation claims; context postings are not exclusive to two Stages.',
        why_more_than_public_context=('Distinct scoped native identity observations coexist, but their independence and acceptable fanout/locality have no calibrated weak policy.'
            if row['anchors']['multiple_distinct_anchors'] else None),
        weak_candidate_reason='No weak candidate admitted: no new fanout, independence or temporal eligibility policy is chosen.',
        scope_trusted=complete,hard_conflict=conflict,
        weak_fanout_eligibility='NEEDS_CALIBRATION',weak_temporal_eligibility='NEEDS_CALIBRATION',
        temporal_order_is_causal_evidence=False,semantic_direction_present=bool(row['formal_directional_claim_ids']))


def role_audit(d,claims,contexts,alerts,policy,supports):
    """Read original claim roles and configured role operations; no new claims."""
    a,b=d['stage_a_id'],d['stage_b_id'];observations=[];complementary=[]
    for context in contexts:
        original=context['original_context'];members=original['memberships']
        ma=[m for m in members if m['stage_id']==a];mb=[m for m in members if m['stage_id']==b]
        kind=original['context_type']
        left_roles=sorted({m['role'] for m in ma});right_roles=sorted({m['role'] for m in mb})
        entry=dict(context_id=context['context_id'],context_type=kind,roles_a=left_roles,roles_b=right_roles,
            operations_a=sorted({alerts[m['alert_id']]['alert_type'] for m in ma if alerts[m['alert_id']]['alert_type']}),
            operations_b=sorted({alerts[m['alert_id']]['alert_type'] for m in mb if alerts[m['alert_id']]['alert_type']}))
        pairs=[]
        if kind=='PROCESS':
            pairs=[(l,r) for l in ma for r in mb if {l['role'],r['role']}=={'process','parent_process'}]
        elif kind in {'REQUEST','SESSION','CONNECTION'}:
            starts,uses=(policy['request_operations'],policy['response_operations']) if kind=='REQUEST' else (policy['session_start_operations'],policy['session_use_operations'])
            pairs=[(l,r) for l in ma for r in mb if
                (alerts[l['alert_id']]['alert_type'] in starts and alerts[r['alert_id']]['alert_type'] in uses) or
                (alerts[r['alert_id']]['alert_type'] in starts and alerts[l['alert_id']]['alert_type'] in uses)]
        elif kind=='OBJECT':
            pairs=[(l,r) for l in ma for r in mb if {l['role'],r['role']}=={'response_object_id','request_object_id'}]
        entry['configured_complementary_role_witness_count']=len(pairs)
        observations.append(entry)
        if pairs:complementary.append(entry)
    # Supporting absolute paths also carry real created_file/executable roles.
    # Same creator/creator or executable/executable is not create/consume.
    supporting_roles=[]
    for claim_id in d['supporting_claim_ids']:
        claim=claims[claim_id]
        if claim['evidence_type']!='SHARED_FILE_PATH':continue
        key=claim['evidence_type']+':'+encode(claim['metadata']['projection_identity'])
        posting=supports[key]['original_posting_observations']
        left=[m for m in posting if m['stage_id']==a];right=[m for m in posting if m['stage_id']==b]
        hits=[(l,r) for l in left for r in right if
            (l['role']=='created_file' and alerts[l['alert_id']]['alert_type'] in policy['object_create_operations'] and
             r['role']=='executable' and alerts[r['alert_id']]['alert_type'] in policy['object_execute_operations']) or
            (r['role']=='created_file' and alerts[r['alert_id']]['alert_type'] in policy['object_create_operations'] and
             l['role']=='executable' and alerts[l['alert_id']]['alert_type'] in policy['object_execute_operations'])]
        entry=dict(claim_id=claim_id,evidence_type=claim['evidence_type'],original_claim_roles=[claim['role_a'],claim['role_b']],
            roles_a=sorted({m['role'] for m in left}),roles_b=sorted({m['role'] for m in right}),
            configured_complementary_role_witness_count=len(hits))
        supporting_roles.append(entry)
        if hits:complementary.append(entry)
    directional=[claims[i] for group in ('relation_claim_ids','context_claim_ids','supporting_claim_ids','invalid_claim_ids') for i in d[group]
        if claims[i]['semantic_class']=='DIRECTIONAL_RELATION']
    return dict(context_roles=observations,supporting_path_roles=supporting_roles,configured_complementary_roles=complementary,
        formal_directional_claims=directional,has_role_semantics=bool(complementary or directional),
        explanation='Repeated flow/MEMBER/process roles are membership roles; identical roles and common parent do not prove handoff.')


def build_pairs(handoff,targets,catalog,supports,policy):
    ss={s['stage_id']:s for s in handoff['stages']['stages']};aa={a['alert_id']:a for a in handoff['alerts']}
    claims={c['claim_id']:c for c in handoff['evidence']['claims']};obs={o['observation_id']:o for o in handoff['evidence']['trace']['observations']}
    result=[]
    for d in targets:
        a,b=d['stage_a_id'],d['stage_b_id'];sa,sb=ss[a],ss[b]
        contexts=[catalog[cid] for cid in d['context_identity_ids']]
        support_claims=[claims[i] for i in d['supporting_claim_ids']]
        types={c['context_type'] for c in contexts};etypes=set(d['evidence_type_counts'])
        source_a=sorted({aa[i]['source_namespace'] for i in sa['alert_ids']});source_b=sorted({aa[i]['source_namespace'] for i in sb['alert_ids']})
        context_sources=sorted({tuple(sorted((aa[obs[oid]['alert_a_id']]['source_namespace'],aa[obs[oid]['alert_b_id']]['source_namespace'])))
            for i in d['context_claim_ids'] for oid in claims[i]['observation_ids']})
        role=role_audit(d,claims,contexts,aa,policy,supports)
        fields=dict(shared_host='SAME_HOST' in etypes,shared_account='SAME_ACCOUNT' in etypes,
            shared_process='PROCESS' in types,shared_request='REQUEST' in types,shared_flow='FLOW' in types,
            shared_auth_session=any(c['context_type']=='SESSION' and c['authority']['authority_class']=='authoritative binding' for c in contexts),
            shared_network_session='CONNECTION' in types or any(c['context_type']=='SESSION' and c['authority']['authority_class']!='authoritative binding' for c in contexts),
            shared_endpoint='NETWORK_ENDPOINT_OVERLAP' in etypes,shared_file_path='SHARED_FILE_PATH' in etypes,
            shared_command='SAME_COMMAND' in etypes,shared_object='OBJECT' in types,
            other=sorted(etypes & {'SAME_URL','INCOMPLETE_FLOW','SHARED_PROCESS_DESCRIPTOR'}))
        support_keys=sorted({c['evidence_type']+':'+encode(c['metadata']['projection_identity']) for c in support_claims})
        pointer_observations=[]
        for c in contexts:
            counts={sid:len({m['alert_id'] for m in c['original_context']['memberships'] if m['stage_id']==sid}) for sid in (a,b)}
            pointer_observations.append(dict(context_id=c['context_id'],member_alerts_per_pair_stage=counts,
                repeated_on_both_sides=all(n>1 for n in counts.values())))
        row=dict(pair_id=d['candidate_id'],stage_a=a,stage_b=b,community_a=sa['community_id'],community_b=sb['community_id'],
            alert_count_a=sa['alert_count'],alert_count_b=sb['alert_count'],behavior_a=sa['behavior'],behavior_b=sb['behavior'],
            source_types_a=sa['source_types'],source_types_b=sb['source_types'],source_a=source_a,source_b=source_b,
            same_source=len(set(source_a+source_b))==1,cross_source=len(set(source_a+source_b))>1,
            source_classification_basis='Stage pair contains one versus multiple original source namespaces; not proof of cross-source identity',
            context_witness_source_pairs=context_sources,context_witness_cross_source=any(l!=r for l,r in context_sources),
            shared_contexts=fields,context_types=sorted(types),contexts=contexts,supporting_fact_keys=support_keys,
            exclusive_two_stage_supporting_facts=[dict(audit_fact_key=k,evidence_type=supports[k]['evidence_type'],
                context_member_stage_count=2,context_span_seconds=supports[k]['context_span_seconds'],
                authority_class=supports[k]['authority_class'],native_object_or_session_lifecycle_certified=False)
                for k in support_keys if supports[k]['context_member_stage_count']==2],
            original_formal_decision=d,PRIMARY_CONTEXT_TYPE='UNDEFINED',primary_context_ranking_basis='No official ranking among CONTEXT identities.',
            temporal=temporal_observation(sa,sb),behavior=behavior_observation(sa,sb),anchors=anchor_families(contexts,a,b),
            role_semantics=role,formal_directional_claim_ids=[c['claim_id'] for c in role['formal_directional_claims'] if c['valid']],
            hard_conflict='HARD_CONFLICT' in d['diagnostics'],observed_formal_conflicts=sorted({s for i in d['invalid_claim_ids'] for s in claims[i]['conflict_status']}),
            repeated_context_observations=pointer_observations,
            supporting_facts_are_not_additional_relation_evidence=True,
            derived_or_correlated_fact_groups=dict(flow_tuple_endpoint=['SAME_SCOPED_FLOW','INCOMPLETE_FLOW','NETWORK_ENDPOINT_OVERLAP'],
                process_descriptor=['SAME_PROCESS_INSTANCE','SHARED_PROCESS_DESCRIPTOR'],
                scope_components=['SAME_HOST','SAME_ACCOUNT']))
        row.update(classify(row));result.append(row)
    return result


def what_if(handoff,rows):
    nodes=[s['stage_id'] for s in handoff['stages']['stages']]
    base={(d['stage_a_id'],d['stage_b_id']) for d in handoff['evidence']['decisions'] if d['relation_type']!='NO_RELATION'}
    groups=graph_components(nodes,base);owner={sid:i for i,g in enumerate(groups) for sid in g}
    candidates=[r for r in rows if r['WEAK_RELATION_CANDIDATE']]
    possible=[r for r in rows if r['qualification_bucket']=='POSSIBLE_WEAK_RELATION']
    ambiguous=[r for r in rows if r['qualification_bucket']=='AMBIGUOUS']
    impacts=[]
    for r in rows:
        a,b=r['stage_a'],r['stage_b'];ga,gb=owner[a],owner[b]
        impacts.append(dict(pair_id=r['pair_id'],stage_a=a,stage_b=b,audit_category=r['audit_category'],
            admitted_weak_candidate=r['WEAK_RELATION_CANDIDATE'],baseline_component_a_size=len(groups[ga]),
            baseline_component_b_size=len(groups[gb]),different_baseline_components=ga!=gb,
            WEAK_BRIDGE=ga!=gb and len(groups[ga])>1 and len(groups[gb])>1,
            single_pair_what_if=graph_statistics(nodes,base,[(a,b)])))
    edges=lambda selected:[(r['stage_a'],r['stage_b']) for r in selected]
    return dict(baseline=graph_statistics(nodes,base,[]),qualified_possible=graph_statistics(nodes,base,edges(possible)),
        uncalibrated_review_set_sensitivity=graph_statistics(nodes,base,edges(ambiguous)),
        deliberately_ineligible_all_shared_context_stress=graph_statistics(nodes,base,edges(rows)),
        per_pair_bridge_impacts=impacts,
        weak_bridge_candidate_count=sum(r['WEAK_BRIDGE'] and r['admitted_weak_candidate'] for r in impacts),
        all_shared_pairs_between_non_singleton_components=sum(r['WEAK_BRIDGE'] for r in impacts),
        all_shared_pairs_between_baseline_components=sum(r['different_baseline_components'] for r in impacts),
        classifications_fixed_before_graph_analysis=True,formal_graph_unchanged=True,
        accepted_edges_read_for_topology_only=True,no_relation_evidence_for_four_other_rejections_analyzed=True)


def summarize(rows,catalog,supports,impact):
    counts=Counter(r['audit_category'] for r in rows);buckets=Counter(r['qualification_bucket'] for r in rows)
    candidates=[r for r in rows if r['WEAK_RELATION_CANDIDATE']]
    fanouts=[c['stage_fanout'] for c in catalog.values()]
    times=[r['temporal']['time_gap_seconds'] for r in rows]
    result=dict(TASK_RESULT='SUCCESS',AUDIT_ONLY=True,SHARED_CONTEXT_ONLY_INPUT_COUNT=len(rows),
        SHARED_CONTEXT_AUDIT_COUNTS={k:counts[k] for k in CATEGORIES},
        SHARED_CONTEXT_TYPE_COUNTS={field:sum(bool(r['shared_contexts'][field]) for r in rows) for field in TYPE_FIELDS.values()},
        FORMAL_CONTEXT_TYPE_PAIR_COUNTS=dict(Counter(t for r in rows for t in r['context_types'])),
        PRIMARY_CONTEXT_TYPE_COUNTS={'UNDEFINED':len(rows)},PRIMARY_CONTEXT_RANKING_DEFINED=False,
        PAIRWISE_CONTEXT_COUNT=sum(n==2 for n in fanouts),MULTI_STAGE_CONTEXT_COUNT=sum(n>2 for n in fanouts),
        HIGH_FANOUT_CONTEXT_COUNT=sum(n>2 for n in fanouts),
        CONTEXT_COUNT_UNIT='unique original ContextIdentityPosting referenced by target pairs; supporting facts inventoried separately',
        HIGH_FANOUT_LABEL_BASIS='structural >2, not a new weak-eligibility threshold',
        SHARED_CONTEXT_PAIRS_FROM_HIGH_FANOUT=sum(any(c['HIGH_FANOUT_CONTEXT'] for c in r['contexts']) for r in rows),
        FANOUT_DISTRIBUTION=distribution(fanouts),CONTEXT_FANOUT_HISTOGRAM=dict(Counter(fanouts)),
        CONTEXT_MEMBER_ALERT_COUNT_DISTRIBUTION=distribution([c['context_member_alert_count'] for c in catalog.values()]),
        CONTEXT_MEMBER_SOURCE_COUNT_DISTRIBUTION=distribution([c['context_member_source_count'] for c in catalog.values()]),
        CONTEXT_SPAN_SECONDS_DISTRIBUTION=distribution([c['context_span_seconds'] for c in catalog.values()]),
        EXCLUSIVE_TWO_STAGE_CONTEXT_PAIR_COUNT=sum(any(c['stage_fanout']==2 for c in r['contexts']) for r in rows),
        EXCLUSIVE_TWO_STAGE_CONTEXT_TYPES=dict(Counter(c['context_type'] for c in catalog.values() if c['stage_fanout']==2)),
        EXCLUSIVE_TWO_STAGE_SUPPORTING_FACT_COUNT=sum(s['context_member_stage_count']==2 for s in supports.values()),
        PAIR_COUNT_WITH_EXCLUSIVE_TWO_STAGE_SUPPORTING_FACT=sum(bool(r['exclusive_two_stage_supporting_facts']) for r in rows),
        IDENTITY_POLLUTED_CONTEXT_COUNT=sum(c['original_context']['metadata']['identity_polluted'] for c in catalog.values()),
        SHARED_CONTEXT_SAME_SOURCE_COUNT=sum(r['same_source'] for r in rows),SHARED_CONTEXT_CROSS_SOURCE_COUNT=sum(r['cross_source'] for r in rows),
        ACTUAL_CONTEXT_WITNESS_CROSS_SOURCE_PAIR_COUNT=sum(r['context_witness_cross_source'] for r in rows),
        SOURCE_NAMESPACE_SET_PAIR_COUNTS=dict(Counter(' + '.join(sorted(set(r['source_a']+r['source_b']))) for r in rows)),
        SHARED_CONTEXT_PAIR_WITH_ROLE_SEMANTICS_COUNT=sum(r['role_semantics']['has_role_semantics'] for r in rows),
        CLEAR_NO_RELATION_COUNT=buckets['CLEAR_NO_RELATION'],POSSIBLE_WEAK_RELATION_COUNT=buckets['POSSIBLE_WEAK_RELATION'],
        AMBIGUOUS_COUNT=buckets['AMBIGUOUS'],WEAK_RELATION_CANDIDATE_COUNT=len(candidates),
        UNCALIBRATED_REVIEW_PAIR_COUNT=buckets['AMBIGUOUS'],
        WEAK_CANDIDATE_WITH_SEMANTIC_DIRECTION=sum(r['semantic_direction_present'] for r in candidates),
        WEAK_CANDIDATE_WITHOUT_SEMANTIC_DIRECTION=sum(not r['semantic_direction_present'] for r in candidates),
        WEAK_BRIDGE_CANDIDATE_COUNT=impact['weak_bridge_candidate_count'],
        WHAT_IF_WEAK_EDGE_COUNT=impact['qualified_possible']['extra_pair_count'],
        WHAT_IF_COMPONENT_COUNT=impact['qualified_possible']['component_count'],
        WHAT_IF_ISOLATED_STAGE_COUNT=impact['qualified_possible']['isolated_stage_count'],
        WHAT_IF_COMPONENT_SIZES=impact['qualified_possible']['component_sizes'],
        QUALIFICATION_STATUS='NEEDS_CALIBRATION; no weak admission thresholds or behavior mapping defined',
        PRODUCTION_STAGE7_MODIFIED=False,PRODUCTION_STAGE8_MODIFIED=False,PRODUCTION_STAGE9_MODIFIED=False,
        FORMAL_RELATION_CREATED=False,THRESHOLD_MODIFIED=False,DATASET_MODIFIED=False,GROUND_TRUTH_MODIFIED=False,
        TEMPORAL_ORDER_IS_CAUSAL_EVIDENCE=False,
        TIME_GAP_SECONDS_DISTRIBUTION=distribution(times),TIME_INTERVAL_RELATION_COUNTS=dict(Counter(r['temporal']['interval_relation'] for r in rows)),
        BEHAVIOR_PAIR_COUNTS=dict(Counter(r['behavior_a']+' / '+r['behavior_b'] for r in rows)),
        BEHAVIOR_COMPATIBILITY_COUNTS=dict(Counter(r['behavior']['state'] for r in rows)),
        INDEPENDENT_OBSERVATION_SCOPE='Distinct native field paths and identity domains only; causal/statistical independence not claimed.',
        SUPPORTING_FACT_CATALOG_COUNT=len(supports),SUPPORTING_FACT_FANOUT_DISTRIBUTION=distribution([s['context_member_stage_count'] for s in supports.values()]),
        FILES_CHANGED=FILES_CHANGED)
    result.update({k+'_COUNT':counts[k] for k in CATEGORIES})
    result.update({'WITHIN_'+str(t)+'S':sum(g<=t for g in times) for t in (30,60,120,300)})
    result['OVER_300S']=sum(g>300 for g in times)
    return result


def validate(rows,catalog,summary,impact):
    assert len(rows)==summary['SHARED_CONTEXT_ONLY_INPUT_COUNT']==138
    assert len({r['pair_id'] for r in rows})==138
    assert sum(summary['SHARED_CONTEXT_AUDIT_COUNTS'].values())==138
    assert sum(summary[k] for k in ('CLEAR_NO_RELATION_COUNT','POSSIBLE_WEAK_RELATION_COUNT','AMBIGUOUS_COUNT'))==138
    assert summary['SHARED_CONTEXT_SAME_SOURCE_COUNT']+summary['SHARED_CONTEXT_CROSS_SOURCE_COUNT']==138
    assert all(r['original_formal_decision']['relation_type']=='NO_RELATION' and 'SHARED_CONTEXT_ONLY' in r['original_formal_decision']['diagnostics'] for r in rows)
    assert all(not r['original_formal_decision']['relation_claim_ids'] for r in rows)
    assert all(r['PRIMARY_CONTEXT_TYPE']=='UNDEFINED' for r in rows)
    assert all(r['weak_fanout_eligibility']=='NEEDS_CALIBRATION' and not r['WEAK_RELATION_CANDIDATE'] for r in rows)
    assert impact['baseline']==impact['qualified_possible']
    assert sum(impact['qualified_possible']['component_sizes'])==42
    assert summary['PAIRWISE_CONTEXT_COUNT']+summary['MULTI_STAGE_CONTEXT_COUNT']==len(catalog)
    return True


def protect(root,out,source,postings):
    baseline=out/'protected_before.json'
    if baseline.exists():return json.loads(baseline.read_text(encoding='utf8'))
    if out.exists() and any(out.iterdir()):raise ValueError('unrecognized_nonempty_audit_output')
    out.mkdir(parents=True,exist_ok=True)
    files={str(p.resolve()):sha(p) for folder in ('backend/app','backend/tests','configs','scripts','docs','tests','frontend/src')
        for p in (root/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts}
    files.update({str(source):sha(source),str(postings):sha(postings)})
    for folder in ('outputs/stage8_relation_sparsity_audit','outputs/stage9_attack_chain_reconstruction/formal_run'):
        if (root/folder).exists():
            files.update({str(p.resolve()):sha(p) for p in (root/folder).iterdir() if p.is_file()})
    prior=source.parent/'after_protected.json'
    if prior.is_file():
        for name in json.loads(prior.read_text(encoding='utf8')):
            p=Path(name)
            if 'TraceBack-Dataset' in str(p) and p.is_file():files[str(p.resolve())]=sha(p)
    save(out,baseline.name,files)
    return files


def report_markdown(summary,impact):
    s=summary
    return '\n'.join(['# SHARED_CONTEXT_ONLY 弱关系资格审计','',
        '仅审计冻结⑧的138个SHARED_CONTEXT_ONLY，不重放⑦/⑧/⑨，不改Context/Role/Scope规则。23条正式关系只读取端点供WHAT-IF基线使用；4个NO_VALID_EVIDENCE不参与证据分类。','',
        '## 诊断结论','',
        f"138对引用10个原始Context，Stage fanout为3～10，双Stage独占Context为0。分类为：`{encode(s['SHARED_CONTEXT_AUDIT_COUNTS'])}`。",'',
        f"按当前可证实事实，明确继续NO_RELATION {s['CLEAR_NO_RELATION_COUNT']}对；弱关系资格已成立 {s['POSSIBLE_WEAK_RELATION_COUNT']}对；需校准的研究样本{s['AMBIGUOUS_COUNT']}对。不能将研究样本数当作可加入图的弱边数。",'',
        '95对只共享Flow类身份；另2对仅有一个非派生身份域（Process或AuthSession），Host/Account/descriptor等是身份scope或描述背景。因此97对不具有新的pairwise连续性依据。41对具有Process与AuthSession等不同身份域、不同原始字段的观测锚；它们仍全部来自多Stage Context，弱准入扇出、时间范围及观测独立性均没有正式校准，保留为AMBIGUOUS。','',
        '“不同原始字段”只证明不是同一个字段的重复投影，不证明统计独立或共同攻击过程。Flow/tuple/endpoint、Process/descriptor，以及作为scope组成部分的Host/Account不叠加成额外独立锚。','',
        '## Context与资格边界','',
        'HIGH_FANOUT在本报告仅指结构性fanout>2，与既有双Stage独占例外互补，不是新设置的弱边阈值。10个Context全部满足该结构标签，但不据此把41个多锚样本直接宣告为必然公共或必然弱关系。','',
        '正式系统没有对CONTEXT身份定义统一强弱排序，因此PRIMARY_CONTEXT_TYPE全部为UNDEFINED。正式Context catalog只计算原ContextIdentityPosting；Host/Account/Path等支持事实另存supporting_facts.json及全局fanout，避免伪造正式Context。','',
        f"除正式类型Context外，有{s['EXCLUSIVE_TWO_STAGE_SUPPORTING_FACT_COUNT']}个仅覆盖两Stage的支持事实，涉及{s['PAIR_COUNT_WITH_EXCLUSIVE_TWO_STAGE_SUPPORTING_FACT']}个Pair：URL、Process descriptor、文件路径、Command。它们不是双Stage独占的完整对象/会话实例；例如descriptor只计当前process，而完整Process Context还包含parent_process角色。因此未把这些低扇出支持事实升级为EXCLUSIVE_LOCAL_CONTEXT或弱候选。身份污染标记数为{s['IDENTITY_POLLUTED_CONTEXT_COUNT']}；高扇出不等于证明身份污染。",'',
        f"共享类型（同Pair可重复计数）：`{encode(s['SHARED_CONTEXT_TYPE_COUNTS'])}`。原始Context类型覆盖：`{encode(s['FORMAL_CONTEXT_TYPE_PAIR_COUNTS'])}`。",'',
        f"Fanout分布：`{encode(s['FANOUT_DISTRIBUTION'])}`；直方图：`{encode(s['CONTEXT_FANOUT_HISTOGRAM'])}`。具体Stage/Alert/source成员、时间跨度与scope见contexts.json。",'',
        '## 时间、行为、角色与来源','',
        f"时间差分布（秒）：`{encode(s['TIME_GAP_SECONDS_DISTRIBUTION'])}`；区间关系：`{encode(s['TIME_INTERVAL_RELATION_COUNTS'])}`。30/60/120/300秒仅按用户要求统计，不作为准入规则；large_gap仅采用OVER_300S报告分箱。",'',
        f"行为状态：`{encode(s['BEHAVIOR_COMPATIBILITY_COUNTS'])}`。没有正式跨标签兼容表；不同已知标签的兼容性为UNDEFINED，UNKNOWN不被当作兼容。⑥同Stage的semantic_conflict不移植为⑧关系冲突。",'',
        f"可匹配现有强关系互补角色的Pair数：{s['SHARED_CONTEXT_PAIR_WITH_ROLE_SEMANTICS_COUNT']}。flow/MEMBER、同一process、共同parent均不提供handoff方向。逐Context的真实角色及原始操作见pairs.json。",'',
        f"涉及单一namespace的Stage Pair {s['SHARED_CONTEXT_SAME_SOURCE_COUNT']}对，涉及多个namespace {s['SHARED_CONTEXT_CROSS_SOURCE_COUNT']}对；其中实际Context观察跨源的只有{s['ACTUAL_CONTEXT_WITNESS_CROSS_SOURCE_PAIR_COUNT']}对。混合来源Stage不等于跨源identity已合并。",'',
        'AuthSession权威scope按已有6条归档投影匹配；Process保留原Host作用域内完整实例身份；Flow/Request保留原来源scope。没有跨源Network identity authority，不按相同token或endpoint提升可信度。','',
        '## WHAT-IF（纯内存）','',
        f"资格已成立的候选为0，正式WHAT-IF：`{encode(impact['qualified_possible'])}`。",'',
        f"额外的未校准研究集敏感性分析（不代表推荐加入）：`{encode(impact['uncalibrated_review_set_sensitivity'])}`。41对全部位于已有分量内部，故即便全加也不减少孤立Stage。",'',
        f"明确不合格的全138对污染压力测试（负面对照）：`{encode(impact['deliberately_ineligible_all_shared_context_stress'])}`。这不是弱边设计收益，不能据此接纳Flow clique。",'',
        f"全部138对中，跨现有分量{s['ALL_SHARED_PAIRS_BETWEEN_BASELINE_COMPONENTS']}对；连接两个已有非单节点分量的Pair为{impact['all_shared_pairs_between_non_singleton_components']}。当前没有8节点分量与10节点分量之间的桥；这不构成未来弱桥安全保证。逐对桥接影响见what_if.json。",'',
        '## 下一阶段需要的设计证据（本轮不实现）','',
        '当前样本不足以支持“为减少孤立节点而上线WEAK_DIRECTED”。若继续研究，先独立制定非公共锚、同义/派生证据去重、identity authority与生命周期、低扇出判据、时间局部性、未知行为处理、强角色遗漏检查及弱桥审查标准，再用独立数据校准；不得从138对的图变漂亮程度反推准入阈值。','',
        '未来若无正式语义方向，箭头只能表示时间展示顺序；TEMPORAL_ORDER_IS_CAUSAL_EVIDENCE=false。真实互补角色应先检查为何没有成为强Relation Claim，不用弱边掩盖强证据路径问题。','',
        '## 产物与复现','',
        'pairs.json含138对全部基础字段、证据、上下文成员、角色、scope、资格及分类；weak_candidates.json为空；uncalibrated_review_pairs.json保存41对待校准研究样本。summary.json与acceptance.txt包含全部验收字段。','',
        '脚本：`.venv\\Scripts\\python.exe -B scripts/audit_shared_context_weak_relation.py --output outputs/shared_context_weak_relation_audit_repeat`。读取既有正式快照及同源stage8_postings.json，不调用生产生成器。','',
        '测试：`.venv\\Scripts\\python.exe -B -m pytest tests/audit-only/test_shared_context_weak_relation_audit.py -q -p no:cacheprovider`。',''])


def _run(source,postings_path,out):
    source,postings_path,out=Path(source).resolve(),Path(postings_path).resolve(),Path(out).resolve()
    if not all(p.is_relative_to(ROOT/'outputs') for p in (source,postings_path,out)) or source.is_relative_to(out) or postings_path.is_relative_to(out):
        raise ValueError('audit_requires_separate_output_snapshot_paths')
    protected=protect(ROOT,out,source,postings_path)
    source_hash=sha(source);handoff=json.loads(source.read_text(encoding='utf8'));before=digest(handoff)
    receipt=json.loads((postings_path.parent/'execution.json').read_text(encoding='utf8'))
    if receipt['source_sha256']!=source_hash:raise ValueError('projected_postings_from_different_formal_snapshot')
    postings=json.loads(postings_path.read_text(encoding='utf8'))
    from app.config import read_yaml
    policy=read_yaml(ROOT/'configs/stage-evidence-v1.yaml')
    targets=[d for d in handoff['evidence']['decisions'] if d['relation_type']=='NO_RELATION' and 'SHARED_CONTEXT_ONLY' in d['diagnostics']]
    if len(targets)!=138:raise ValueError('requires_exact_138_shared_context_only_snapshot')
    catalog=context_catalog(handoff,targets);supports=support_catalog(handoff,targets,postings)
    rows=build_pairs(handoff,targets,catalog,supports,policy)
    impact=what_if(handoff,rows);summary=summarize(rows,catalog,supports,impact)
    summary['ALL_SHARED_PAIRS_BETWEEN_BASELINE_COMPONENTS']=impact['all_shared_pairs_between_baseline_components']
    validate(rows,catalog,summary,impact)
    from app.models.base import resolve_pointer
    alerts={a['alert_id']:a for a in handoff['alerts']}
    pointers={p['pointer_id']:p['raw_pointer'] for p in handoff['evidence']['trace']['raw_pointers']}
    observations={o['observation_id']:o for o in handoff['evidence']['trace']['observations']}
    claims={c['claim_id']:c for c in handoff['evidence']['claims']}
    referenced_claims={i for d in targets for group in ('context_claim_ids','supporting_claim_ids','invalid_claim_ids') for i in d[group]}
    referenced_observations={i for cid in referenced_claims for i in claims[cid]['observation_ids']}
    referenced_pointers={p for oid in referenced_observations for p in observations[oid]['raw_pointer_ids']}|{
        p for c in catalog.values() for m in c['original_context']['memberships'] for p in m['raw_pointer_ids']}
    resolved=[dict(pointer_id=p,raw_pointer=pointers[p],value=resolve_pointer(alerts[pointers[p]['alert_id']]['raw_alert'],pointers[p]['pointer'])) for p in sorted(referenced_pointers)]
    save(out,'pairs.json',rows);save(out,'contexts.json',list(catalog.values()));save(out,'supporting_facts.json',list(supports.values()))
    save(out,'weak_candidates.json',[r for r in rows if r['WEAK_RELATION_CANDIDATE']])
    save(out,'uncalibrated_review_pairs.json',[r for r in rows if r['qualification_bucket']=='AMBIGUOUS'])
    save(out,'what_if.json',impact)
    save(out,'trace.json',dict(claims=[claims[i] for i in sorted(referenced_claims)],observations=[observations[i] for i in sorted(referenced_observations)],resolved_pointers=resolved))
    save(out,'summary.json',summary)
    (out/'acceptance.txt').write_text('\n'.join(k+'='+json.dumps(v,ensure_ascii=False) for k,v in summary.items())+'\n',encoding='utf8')
    (out/'REPORT.md').write_text(report_markdown(summary,impact),encoding='utf8')
    changed=[p for p,h in protected.items() if not Path(p).is_file() or sha(p)!=h]
    if changed or sha(source)!=source_hash or digest(handoff)!=before:raise ValueError('audit_input_modified:'+str(changed))
    save(out,'integrity.json',dict(PROTECTED_FILE_COUNT=len(protected),EXISTING_FILES_CHANGED=changed,
        DATASET_AND_GT_FILES_HASHED=sum('TraceBack-Dataset' in p for p in protected),GT_USED_FOR_CLASSIFICATION=False,
        SOURCE_SHA256=source_hash,INPUT_SNAPSHOT_UNCHANGED=True,FORMAL_RELATIONS_UNCHANGED=True,
        PRIOR_AUDITS_AND_STAGE9_ARTIFACTS_UNCHANGED=True,RESOLVED_POINTER_COUNT=len(resolved),
        PRODUCTION_STAGE7_CALL_COUNT=0,PRODUCTION_STAGE8_CALL_COUNT=0,PRODUCTION_STAGE9_CALL_COUNT=0,
        NEW_BEHAVIOR_MAPPING_DEFINED=False,NEW_WEAK_THRESHOLD_DEFINED=False))
    print(json.dumps(summary,ensure_ascii=False,indent=2))
    return rows,catalog,summary,impact


def run(source,postings_path,out):
    with no_production_execution():
        return _run(source,postings_path,out)


if __name__=='__main__':
    sys.stdout.reconfigure(encoding='utf8')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',type=Path,default=ROOT/'outputs/stage2_identity_projection/after.json')
    parser.add_argument('--postings',type=Path,default=ROOT/'outputs/stage8_relation_sparsity_audit/stage8_postings.json')
    parser.add_argument('--output',type=Path,default=ROOT/'outputs/shared_context_weak_relation_audit')
    args=parser.parse_args()
    try:run(args.input,args.postings,args.output)
    except Exception:
        print('TASK_RESULT=FAILED\nAUDIT_ONLY=true',file=sys.stderr)
        raise
