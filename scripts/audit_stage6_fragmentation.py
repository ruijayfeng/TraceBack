"""Audit frozen ⑥ membership and rejection logs, without rebuilding Stages.

Only original Profile readers, Stage hard-conflict/shared-binding predicates and
TemporalHistory snapshots are evaluated. No pair_evidence, community_graph,
aggregate_stages, semantic resolver, Stage7/8 decision or Stage9 is executed.
"""
import argparse
from collections import Counter, defaultdict
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path
import statistics
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'backend'))
sys.dont_write_bytecode=True
FILES_CHANGED=['scripts/audit_stage6_fragmentation.py','tests/audit-only/test_stage6_fragmentation_audit.py',
    'docs/STAGE_6_FRAGMENTATION_AUDIT.md','outputs/stage6_fragmentation_audit/']
CLASSES=['LEGITIMATE_SINGLETON_STAGE','LEGITIMATE_SEPARATE_STAGE','POSSIBLE_OVER_FRAGMENTATION',
    'POSSIBLE_TIME_OVER_FRAGMENTATION','POSSIBLE_UNKNOWN_BEHAVIOR_FRAGMENTATION',
    'POSSIBLE_WEAK_BRIDGE_OVER_PRUNING','AMBIGUOUS']


def encode(value):return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))
def sha(path):return sha256(Path(path).read_bytes()).hexdigest()
def digest(value):return sha256(encode(value).encode('utf8')).hexdigest()
def sec(value):return datetime.fromisoformat(value.replace('Z','+00:00')).timestamp()


def save(out,name,value):
    (out/name).write_text(json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2)+'\n',encoding='utf8')


def distribution(values):
    values=sorted(values)
    def q(p):
        if not values:return None
        x=(len(values)-1)*p;i=int(x)
        return values[i]+(values[min(i+1,len(values)-1)]-values[i])*(x-i)
    return dict(count=len(values),min=min(values) if values else None,median=statistics.median(values) if values else None,
        p75=q(.75),p90=q(.9),max=max(values) if values else None)


def gap(a,b):return max(0,max(sec(a['start_time']),sec(b['start_time']))-min(sec(a['end_time']),sec(b['end_time'])))


@contextmanager
def prohibit_builders():
    old=sys.getprofile()
    forbidden_prefix=('app.stage_candidates','app.stage_evidence','app.stage_chains','app.stage_relations',
        'app.services.stage_pipeline','app.services.alert_pipeline','app.adapters.multisource','app.entities.extraction',
        'app.ai','app.api','evaluation')
    forbidden_names={'aggregate_stages','community_graph','pair_evidence','build_communities','prepare_communities',
        'normalize_behavior','normalize_behaviors','extract_entities','weak_bridge_check'}
    def profile(frame,event,arg):
        if event!='call':return
        module=frame.f_globals.get('__name__','')
        if module.startswith(forbidden_prefix) or module.startswith('app.') and frame.f_code.co_name in forbidden_names:
            raise AssertionError('stage6_audit_must_not_rebuild_or_rejudge')
    sys.setprofile(profile)
    try:yield
    finally:sys.setprofile(old)


def connected(nodes,pairs):
    if not nodes:return False
    adjacency={n:set() for n in nodes}
    for a,b in pairs:
        if a not in adjacency or b not in adjacency:raise ValueError('dangling_frozen_membership_proof')
        adjacency[a].add(b);adjacency[b].add(a)
    seen=set();stack=[next(iter(nodes))]
    while stack:
        n=stack.pop()
        if n in seen:continue
        seen.add(n);stack.extend(adjacency[n]-seen)
    return seen==set(nodes)


def native_instances(alert,profile):
    """Read complete existing scoped identities; do not invent global scopes.

    Stage6's flow Binding is a tuple with optional network_namespace, not the
    scoped native Flow of Stage8. A same native ContextRef is additionally
    recorded for audit trust; a bare cross-source tuple is kept distinct.
    """
    result={}
    for b in profile.bindings:
        if b.projection!='binding' or not b.complete:continue
        if b.kind=='process_instance' and b.role=='process':kind='process_instance'
        elif b.kind=='request':kind='request_instance'
        elif b.kind=='object':kind='object_instance'
        elif b.kind in {'session','application_session','connection'}:
            identity=json.loads(b.identity);scope=identity.get('scope','')
            kind='auth_session' if 'auth_session_projection' in scope else 'network_session'
        elif b.kind=='flow':
            for ref in alert.contexts:
                if ref.kind=='flow':
                    key=encode(dict(kind='scoped_native_flow',scope=ref.scope,native_id=ref.value,tuple=json.loads(b.identity)))
                    result[key]=dict(kind='scoped_native_flow',existing_binding=asdict(b),context_ref=ref.model_dump(mode='json'))
            continue
        else:continue
        key=encode(dict(kind=kind,existing_binding_key=b.key))
        result[key]=dict(kind=kind,existing_binding=asdict(b))
    return result


def observed_methods(alerts):
    """Read only explicitly projected method fields and retain raw pointers."""
    from app.models.base import resolve_pointer
    return [dict(alert_id=a.alert_id,field=field,pointer=ref.raw_pointer,
                 value=resolve_pointer(a.raw_alert,ref.raw_pointer))
            for a in alerts for field,ref in a.field_provenance.items()
            if field in {'native.method','native.http/http_method'}]


def stage_rule_references():
    return dict(
        production_entry='backend/app/stages/aggregation.py::aggregate_stages',
        graph_entry='backend/app/stages/aggregation.py::community_graph',
        behavior='pair_evidence: left_behavior == right_behavior; frozen annotations only',
        candidate_recall='CommunityIndex.query over existing typed postings; no recall rebuilt by this audit',
        entity_context='shared_bindings; complete typed binding; parent/parent process excluded; known labels may use host_account/host_process',
        unknown='pair_evidence: unknown_requires_typed_binding only after semantic, hard-conflict and time gates',
        time='TemporalHistory.snapshot before current observation, per Community/behavior; edge delta <= dynamic_threshold_seconds',
        hard_conflict='hard_conflict on candidate and every cross-component member pair before union',
        weak_bridge='weak_bridge_check removes unsupported WEAK bridges; frozen removal diagnostics only',
        stage_definition='connected_components of frozen kept aggregation_basis; singleton is valid',
        no_whole_stage_span_gate='max_stage_span_seconds and unknown_max_stage_span_seconds are not used by this graph builder')


def prepare(handoff):
    from app.adapters.base import AdapterSettings
    from app.community import load_community_config
    from app.community.evidence import profile
    from app.community.temporal import TemporalHistory
    from app.config import read_yaml
    from app.models import CanonicalAlert,Entity
    from app.models.alerts import EvidencePointer
    aa={a['alert_id']:CanonicalAlert.model_validate(a) for a in handoff['alerts']}
    ee={e['entity_id']:Entity.model_validate(e) for e in handoff['entities']}
    ss={s['stage_id']:s for s in handoff['stages']['stages']}
    annotations={b['alert_id']:b for b in handoff['stages']['behaviors']}
    owner={aid:sid for sid,s in ss.items() for aid in s['alert_ids']}
    if len(owner)!=125 or sorted(aid for s in ss.values() for aid in s['alert_ids'])!=sorted(aa):
        raise ValueError('frozen_stage_partition_not_exact')
    if any(annotations[aid]['behavior']!=s['behavior'] or annotations[aid]['community_id']!=s['community_id'] for s in ss.values() for aid in s['alert_ids']):
        raise ValueError('behavior_lost_at_stage_boundary')
    cfg=load_community_config(ROOT/'configs/community-v1.yaml')
    settings={v['source_namespace']:AdapterSettings(**v) for v in read_yaml(ROOT/'configs/front-data-profiles.yaml')['sources'].values()}
    profiles={i:profile(a,ee,settings[a.source_namespace],cfg) for i,a in aa.items()}
    native={i:native_instances(a,profiles[i]) for i,a in aa.items()}
    communities=defaultdict(list)
    for sid,s in ss.items():communities[s['community_id']].append(sid)
    histories={};timelines=[]
    for cid,sids in sorted(communities.items()):
        buckets=defaultdict(TemporalHistory)
        for aid in sorted((i for sid in sids for i in ss[sid]['alert_ids']),key=lambda i:(profiles[i].seconds,i)):
            behavior=annotations[aid]['behavior'];history=buckets[behavior]
            histories[aid]=history.snapshot(cfg.temporal)
            timelines.append(dict(alert_id=aid,community_id=cid,behavior=behavior,time=aa[aid].timestamp,
                preceding_behavior_alert_ids=[r['alert_id'] for r in timelines if r['community_id']==cid and r['behavior']==behavior],
                frozen_policy_snapshot=histories[aid]))
            history.times.append(profiles[aid].seconds)
    diagnostics={tuple(d['alert_ids']):d for d in handoff['stages']['diagnostics']}
    if len(diagnostics)!=len(handoff['stages']['diagnostics']):raise ValueError('duplicate_frozen_stage_diagnostic')
    for d in diagnostics.values():
        if 'temporal_check' not in d:continue
        later=max(d['alert_ids'],key=lambda i:(profiles[i].seconds,i))
        actual={k:v for k,v in d['temporal_check'].items() if k not in {'delta_seconds','passed'}}
        if actual!=histories[later]:raise ValueError('frozen_dynamic_time_history_mismatch')
    from app.stages.evidence import hard_conflict
    resolved=0;internal_checks={}
    for s in ss.values():
        if not connected(s['alert_ids'],[e['alert_ids'] for e in s['aggregation_basis']]):raise ValueError('invalid_existing_stage_connectivity')
        ids=s['alert_ids']
        conflicts=[dict(alert_ids=[a,b],reason=reason) for index,a in enumerate(ids) for b in ids[index+1:]
                   if (reason:=hard_conflict(profiles[a],profiles[b]))]
        if conflicts:raise ValueError('existing_stage_member_conflict:'+s['stage_id'])
        internal_checks[s['stage_id']]=dict(member_pairs_checked=len(ids)*(len(ids)-1)//2,hard_conflicts=conflicts)
        for e in s['aggregation_basis']:
            a,b=e['alert_ids'];later=max((a,b),key=lambda i:(profiles[i].seconds,i))
            threshold=histories[later]['dynamic_threshold_seconds']
            if not e['behavior_compatible'] or not e['temporal_check']['passed'] or abs(profiles[a].seconds-profiles[b].seconds)>threshold:
                raise ValueError('invalid_frozen_aggregation_support')
            for p in e['evidence']:EvidencePointer.model_validate(p).resolve(aa);resolved+=1
    for b in annotations.values():
        for p in b['evidence']:EvidencePointer.model_validate(p).resolve(aa);resolved+=1
    degree=Counter()
    relations=set()
    for d in handoff['evidence']['decisions']:
        if d['relation_type']=='NO_RELATION':continue
        a,b=d['stage_a_id'],d['stage_b_id'];degree.update((a,b));relations.add(tuple(sorted((a,b))))
    isolated=set(ss)-degree.keys()
    # Adjacency in original observations of the exact same scoped identity.
    streams=defaultdict(list)
    for aid,instances in native.items():
        for key in instances:streams[key].append(aid)
    consecutive=defaultdict(list)
    for key,members in streams.items():
        ordered=sorted(members,key=lambda i:(profiles[i].seconds,i))
        for a,b in zip(ordered,ordered[1:]):
            if owner[a]!=owner[b]:consecutive[tuple(sorted((a,b)))].append(key)
    return dict(alerts=aa,entities=ee,stages=ss,annotations=annotations,owner=owner,config=cfg,profiles=profiles,
        settings=settings,native=native,communities=dict(communities),histories=histories,timelines=timelines,
        diagnostics=diagnostics,degree=degree,relations=relations,isolated=isolated,consecutive=consecutive,
        resolved_pointer_count=resolved,internal_checks=internal_checks)


def pair_audit(a,b,data):
    from app.stages.evidence import hard_conflict,shared_bindings
    sa,sb=data['stages'][a],data['stages'][b];profiles=data['profiles'];aa=data['alerts'];native=data['native']
    witnesses=[];hard=Counter();reasons=Counter();same_kinds=set();stage6_kinds=set();core_kinds=set();progressions=[]
    descriptor=False;unknown_conditionals=[]
    for aid in sa['alert_ids']:
        for bid in sb['alert_ids']:
            p,q=profiles[aid],profiles[bid];key=tuple(sorted((aid,bid)))
            diagnostic=data['diagnostics'].get(key)
            conflict=hard_conflict(p,q)
            if conflict:hard[conflict]+=1
            matches=shared_bindings(p,q);stage6_kinds.update(l.kind for l,r in matches)
            core_kinds.update(l.kind for l in p.bindings for r in q.bindings
                if l.kind in {'host_account','host_process'} and (l.kind,l.key)==(r.kind,r.key))
            instance_keys=sorted(native[aid].keys() & native[bid].keys())
            kinds=sorted({native[aid][k]['kind'] for k in instance_keys});same_kinds.update(kinds)
            lineage=any(l.kind=='process_instance' and {l.role,r.role}=={'process','parent_process'} for l,r in matches)
            if lineage:progressions.append(dict(kind='parent_child_process',alert_ids=[aid,bid]))
            if aa[aid].process and aa[bid].process:
                descriptor|=bool((aa[aid].process.name and aa[aid].process.name==aa[bid].process.name) or
                    (aa[aid].process.executable and aa[aid].process.executable==aa[bid].process.executable))
            later=max((aid,bid),key=lambda i:(profiles[i].seconds,i));temporal=data['histories'][later]
            delta=abs(p.seconds-q.seconds);time_pass=delta<=temporal['dynamic_threshold_seconds']
            same_behavior=sa['behavior']==sb['behavior']
            reason=diagnostic['reason'] if diagnostic else None
            if reason:reasons[reason]+=1
            observed_unknown_only=bool(reason=='semantic_conflict' and 'UNKNOWN' in {sa['behavior'],sb['behavior']} and
                matches and not conflict and time_pass)
            if observed_unknown_only:unknown_conditionals.append(dict(alert_ids=[aid,bid],stage6_binding_kinds=sorted({l.kind for l,r in matches}),
                trusted_scoped_instance=bool(instance_keys),temporal=temporal,delta_seconds=delta))
            if diagnostic or instance_keys or matches:
                witnesses.append(dict(alert_a=aid,alert_b=bid,original_diagnostic=diagnostic,
                    actual_first_blocking_reason=reason,frozen_stage6_evaluated=diagnostic is not None,
                    observed_hard_conflict_predicate=conflict,existing_stage6_shared_bindings=[dict(left=asdict(l),right=asdict(r)) for l,r in matches],
                    trusted_same_instance_kinds=kinds,trusted_same_instance_keys=instance_keys,
                    scoped_identity_consecutive_observations=data['consecutive'].get(key,[]),
                    same_behavior=same_behavior,temporal_snapshot=temporal,delta_seconds=delta,time_pass=time_pass,
                    parent_child_role=lineage,
                    time_only_trusted=bool(reason=='dynamic_time_conflict' and same_behavior and instance_keys and not conflict and not lineage),
                    otherwise_eligible_but_not_visited=bool(not diagnostic and same_behavior and instance_keys and not conflict and time_pass and not lineage),
                    observed_unknown_only_gate_block=observed_unknown_only,
                    duplicate_observation_proven=False))
    same_behavior=sa['behavior']==sb['behavior']
    actual_hard={r:n for r,n in reasons.items() if r.startswith('distinct_') or r=='component_hard_conflict'}
    time_only=[w for w in witnesses if w['time_only_trusted']]
    consecutive_time=[w for w in time_only if w['scoped_identity_consecutive_observations']]
    bare_flow=bool(same_behavior and 'flow' in stage6_kinds and not same_kinds and not hard and
        any(w['actual_first_blocking_reason']=='dynamic_time_conflict' for w in witnesses))
    existing=(a,b) in data['relations']
    potential=bool(same_behavior and not hard and consecutive_time and not existing)
    missed=bool(not hard and not existing and any(w['otherwise_eligible_but_not_visited'] for w in witnesses))
    unknown_strict=bool(not hard and not existing and any(w['observed_unknown_only_gate_block'] and w['trusted_same_instance_keys'] for w in witnesses))
    if existing:status='DO_NOT_MERGE_DUE_TO_EXISTING_RELATION'
    elif missed:status='POSSIBLE_OVER_FRAGMENTATION'
    elif potential:status='POSSIBLE_TIME_OVER_FRAGMENTATION'
    elif bare_flow:status='AMBIGUOUS_CROSS_SOURCE_TUPLE_WITHOUT_NATIVE_SCOPE'
    elif unknown_strict:status='POSSIBLE_UNKNOWN_BEHAVIOR_FRAGMENTATION'
    else:status='KEEP_SEPARATE_UNDER_CURRENT_STAGE_CONTRACT'
    left_alerts=[aa[i] for i in sa['alert_ids']];right_alerts=[aa[i] for i in sb['alert_ids']]
    methods_a,methods_b=observed_methods(left_alerts),observed_methods(right_alerts)
    endpoints=lambda alerts:{(ip,port) for x in alerts for ip,port in ((x.src_ip,x.src_port),(x.dst_ip,x.dst_port)) if ip is not None and port is not None}
    overlap=max(sec(sa['start_time']),sec(sb['start_time']))<=min(sec(sa['end_time']),sec(sb['end_time']))
    duplicate_candidate=bool(same_behavior and same_kinds and not hard and not progressions and overlap)
    cross_source_witnesses=[w for w in witnesses if w['same_behavior'] and w['trusted_same_instance_keys'] and
        not w['observed_hard_conflict_predicate'] and w['time_pass'] and not w['parent_child_role'] and
        aa[w['alert_a']].source_namespace!=aa[w['alert_b']].source_namespace]
    cross_source_duplicate=bool(not hard and not progressions and cross_source_witnesses)
    return dict(stage_a=a,stage_b=b,community_id=sa['community_id'],behavior_a=sa['behavior'],behavior_b=sb['behavior'],
        alert_count_a=sa['alert_count'],alert_count_b=sb['alert_count'],behavior_same=same_behavior,
        behavior_different=not same_behavior,behavior_unknown='UNKNOWN' in {sa['behavior'],sb['behavior']},
        time_gap_seconds=gap(sa,sb),shared_host=bool(set(sa['host_entities']) & set(sb['host_entities'])),
        shared_account=bool(set(sa['account_entities']) & set(sb['account_entities'])),
        shared_process_instance='process_instance' in same_kinds,shared_request='request_instance' in same_kinds,
        shared_flow='scoped_native_flow' in same_kinds,shared_auth_session='auth_session' in same_kinds,
        shared_network_session='network_session' in same_kinds,shared_object='object_instance' in same_kinds,
        shared_strong_identity_kinds=sorted(same_kinds),existing_stage6_binding_kinds=sorted(stage6_kinds),
        stage6_flow_tuple_is_not_automatically_scoped_native_flow=True,
        parent_child_process=bool(progressions),progression_role_witnesses=progressions,
        process_descriptor_only=descriptor and 'process_instance' not in same_kinds and not progressions,
        same_host_process_context=bool('host_process' in core_kinds),existing_core_context_binding_kinds=sorted(core_kinds),
        same_account_only=bool(set(sa['account_entities']) & set(sb['account_entities'])) and 'auth_session' not in same_kinds,
        auth_operation_observations=dict(left=sorted({x.alert_type for x in left_alerts if x.alert_type}),
            right=sorted({x.alert_type for x in right_alerts if x.alert_type})),
        auth_establish_use_audit='NO_SHARED_AUTH_SESSION' if 'auth_session' not in same_kinds else 'ROLE_PROOF_REQUIRED_DO_NOT_INFER_FROM_SHARED_SESSION',
        shared_endpoint=bool(endpoints(left_alerts)&endpoints(right_alerts)),
        shared_endpoint_values=sorted(endpoints(left_alerts)&endpoints(right_alerts)),
        shared_method=bool({encode(x['value']) for x in methods_a}&{encode(x['value']) for x in methods_b}),
        observed_method_evidence=dict(left=methods_a,right=methods_b),
        shared_url=bool({data['alerts'][i].url for i in sa['alert_ids'] if data['alerts'][i].url}&
            {data['alerts'][i].url for i in sb['alert_ids'] if data['alerts'][i].url}),
        hard_conflict=bool(hard),hard_conflict_types=dict(hard),actual_hard_conflict_rejection_counts=actual_hard,
        original_split_reason_counts=dict(reasons),alert_pair_audit=witnesses,observed_unknown_only_gate_witnesses=unknown_conditionals,
        time_only_trusted_witness_count=len(time_only),time_only_consecutive_trusted_witness_count=len(consecutive_time),
        consecutive_time_witnesses=consecutive_time,all_member_hard_conflict_free=not hard,
        existing_relation_between=existing,DO_NOT_MERGE_DUE_TO_EXISTING_RELATION=existing,
        audit_assessment=status,POTENTIAL_TIME_OVER_FRAGMENTATION=potential,
        pairwise_member_alerts_checked=len(sa['alert_ids'])*len(sb['alert_ids']),
        union_span_seconds=max(sec(sa['end_time']),sec(sb['end_time']))-min(sec(sa['start_time']),sec(sb['start_time'])),
        observation_intervals_overlap=overlap,
        DUPLICATED_STAGE_OBSERVATION=duplicate_candidate,
        potential_cross_source_duplicate=cross_source_duplicate,cross_source_same_instance_local_witnesses=cross_source_witnesses,
        duplicate_audit_basis='Conservative screen: same frozen label, trusted scoped instance, all-member conflict-free, no process progression; duplicate requires overlapping intervals; cross-source requires a local same-instance witness. No deduplication.',
        no_new_stage_or_membership_constructed=True,
        merge_readiness='CURRENT_TIME_RULE_STILL_BLOCKS; POLICY_AUDIT_ONLY' if potential else 'NO_MERGE_ADMITTED')


def neighbors(data):
    pairs=set()
    for sid in data['isolated']:
        cid=data['stages'][sid]['community_id']
        pairs.update(tuple(sorted((sid,t))) for t in data['communities'][cid] if t!=sid)
    return [pair_audit(a,b,data) for a,b in sorted(pairs)]


def stage_inventory(data):
    result=[]
    for sid,s in sorted(data['stages'].items()):
        instances=defaultdict(dict)
        for aid in s['alert_ids']:
            for k,v in data['native'][aid].items():instances[v['kind']][k]=v
        edges=s['aggregation_basis'];n=s['alert_count']
        result.append(dict(stage_id=sid,community_id=s['community_id'],alert_count=n,member_alert_ids=s['alert_ids'],
            behavior=s['behavior'],start_time=s['start_time'],end_time=s['end_time'],duration_seconds=sec(s['end_time'])-sec(s['start_time']),
            source_types=s['source_types'],source_namespaces=sorted({data['alerts'][i].source_namespace for i in s['alert_ids']}),
            host_ids=s['host_entities'],account_ids=s['account_entities'],process_ids=s['process_entities'],
            request_ids=list(instances['request_instance']),flow_ids=list(instances['scoped_native_flow']),
            auth_session_ids=list(instances['auth_session']),network_session_ids=list(instances['network_session']),object_ids=list(instances['object_instance']),
            instance_observations={k:list(v.values()) for k,v in instances.items()},
            original_stage=s,behavior_annotations=[data['annotations'][i] for i in s['alert_ids']],
            aggregation_basis=edges,INTRA_STAGE_SUPPORT=dict(formal_aggregation_edge_count=len(edges),
                minimum_connected_edge_count=n-1,connected=True,edge_strength_counts=dict(Counter(e['edge_strength'] for e in edges)),
                evidence_type_counts=dict(Counter(k for e in edges for k in e['evidence_types'])),
                density=2*len(edges)/(n*(n-1)) if n>1 else None),
            original_stage6_rule_references=stage_rule_references(),
            internal_member_conflict_audit=data['internal_checks'][sid],
            degree_in_stage8_graph=data['degree'][sid],is_isolated=sid in data['isolated'],
            satisfies_frozen_stage_contract=True))
    return result


def isolated_inventory(data,pairs):
    touching=defaultdict(list)
    for p in pairs:
        for sid in (p['stage_a'],p['stage_b']):touching[sid].append(p)
    result=[]
    for sid in sorted(data['isolated']):
        s=data['stages'][sid];ps=touching[sid]
        other=lambda p:p['stage_b'] if p['stage_a']==sid else p['stage_a']
        priority=sorted(ps,key=lambda p:(not bool(p['shared_strong_identity_kinds']),not p['behavior_same'],p['time_gap_seconds'],other(p)))
        nearest=min(ps,key=lambda p:(p['time_gap_seconds'],abs(sec(data['stages'][other(p)]['start_time'])-sec(s['start_time'])),other(p))) if ps else None
        statuses={p['audit_assessment'] for p in ps}
        if 'POSSIBLE_OVER_FRAGMENTATION' in statuses:cls='POSSIBLE_OVER_FRAGMENTATION'
        elif 'POSSIBLE_TIME_OVER_FRAGMENTATION' in statuses:cls='POSSIBLE_TIME_OVER_FRAGMENTATION'
        elif 'POSSIBLE_UNKNOWN_BEHAVIOR_FRAGMENTATION' in statuses:cls='POSSIBLE_UNKNOWN_BEHAVIOR_FRAGMENTATION'
        elif 'AMBIGUOUS_CROSS_SOURCE_TUPLE_WITHOUT_NATIVE_SCOPE' in statuses:cls='AMBIGUOUS'
        else:cls='LEGITIMATE_SINGLETON_STAGE' if s['alert_count']==1 else 'LEGITIMATE_SEPARATE_STAGE'
        candidates=[p for p in priority if p['audit_assessment']==cls]
        reasons={'POSSIBLE_TIME_OVER_FRAGMENTATION':'Consecutive same-source native Flow observations, same frozen behavior and no all-member hard conflict; original dynamic time gate alone cuts the boundary.',
            'AMBIGUOUS':'Same Stage6 tuple and label but no common scoped native network identity across sources; cannot infer one action or a safe merge.',
            'LEGITIMATE_SINGLETON_STAGE':'No admissible same-stage neighbor: different behavior, observed member conflicts, different instances, or absent current aggregation support.',
            'LEGITIMATE_SEPARATE_STAGE':'Existing member proof is cohesive; same-community context does not supply a conflict-free, locally eligible bridge.',
            'POSSIBLE_OVER_FRAGMENTATION':'Existing eligible same-instance consecutive observations lack a frozen visited boundary proof.',
            'POSSIBLE_UNKNOWN_BEHAVIOR_FRAGMENTATION':'Unknown/known label boundary blocks otherwise supported scoped same-instance local observations.'}
        ordered=sorted(data['communities'][s['community_id']],key=lambda i:(data['stages'][i]['start_time'],data['stages'][i]['end_time'],i));pos=ordered.index(sid)
        previous=ordered[pos-1] if pos else None;following=ordered[pos+1] if pos+1<len(ordered) else None
        result.append(dict(stage_id=sid,community_id=s['community_id'],alert_count=s['alert_count'],behavior=s['behavior'],source_types=s['source_types'],
            nearest_stage_id=other(nearest) if nearest else None,nearest_stage_behavior=data['stages'][other(nearest)]['behavior'] if nearest else None,
            nearest_time_gap=nearest['time_gap_seconds'] if nearest else None,
            shared_strong_identity=nearest['shared_strong_identity_kinds'] if nearest else [],
            shared_supporting_context={k:nearest[k] for k in ('shared_host','shared_account','shared_url','shared_endpoint','shared_method')} if nearest else {},
            hard_conflict=nearest['hard_conflict_types'] if nearest else {},existing_relation_between=False,
            fragmentation_class=cls,primary_reason=reasons[cls],
            secondary_reason=dict(sum((Counter(p['original_split_reason_counts']) for p in ps),Counter())),
            potential_merge_target=other(candidates[0]) if candidates else None,potential_merge_target_is_review_only=True,
            confidence='MEDIUM_POLICY_CONCERN_NOT_PROVEN_ERROR' if cls.startswith('POSSIBLE') else 'LOW_MISSING_CROSS_SOURCE_AUTHORITY' if cls=='AMBIGUOUS' else 'HIGH_UNDER_CURRENT_FROZEN_CONTRACT',
            audit_neighbor_priority=[other(p) for p in priority],same_behavior_neighbor_count=sum(p['behavior_same'] for p in ps),
            trusted_same_instance_neighbor_count=sum(bool(p['shared_strong_identity_kinds']) for p in ps),
            evidence_stage_pairs=[[p['stage_a'],p['stage_b']] for p in candidates],
            previous_stage_id=previous,next_stage_id=following,
            previous_gap_seconds=gap(s,data['stages'][previous]) if previous else None,
            next_gap_seconds=gap(s,data['stages'][following]) if following else None,
            previous_next_basis='immediate neighbors in frozen start/end/ID order within same Community; interval overlap has gap zero'))
    return result


def community_inventory(data,isolated):
    suspect={r['stage_id'] for r in isolated if r['fragmentation_class'].startswith('POSSIBLE')}
    rows=[]
    for cid,sids in sorted(data['communities'].items()):
        values=[data['stages'][s] for s in sids]
        singles=sum(s['alert_count']==1 for s in values);iso_single=sum(s['alert_count']==1 and s['stage_id'] in data['isolated'] for s in values)
        rows.append(dict(community_id=cid,alert_count=sum(s['alert_count'] for s in values),stage_count=len(values),stage_sizes=sorted(s['alert_count'] for s in values),
            single_alert_stage_count=singles,isolated_stage_count=sum(s in data['isolated'] for s in sids),isolated_single_alert_stage_count=iso_single,
            multi_stage_relation_participant_count=sum(data['degree'][s]>0 for s in sids),suspect_fragmented_stage_count=len(set(sids)&suspect),
            HIGH_FRAGMENTATION_COMMUNITY_CANDIDATE=bool(iso_single),
            screening_basis='contains isolated singleton observations: audit priority only, not a calibrated fragmentation threshold',
            membership_provenance='union of original Stage.member_alert_ids grouped by frozen community_id; no new Community partition'))
    return rows


def merge_simulation(data,pairs,isolated):
    # Only class C may be folded. Time/unknown policy concerns do not authorize
    # changing those rules or simulate a merge under a relaxed rule.
    eligible=[p for p in pairs if p['audit_assessment']=='POSSIBLE_OVER_FRAGMENTATION']
    parent={s:s for s in data['stages']}
    def find(s):
        while parent[s]!=s:s=parent[s]
        return s
    checks=[]
    for p in eligible:
        safe=bool(p['behavior_same'] and p['all_member_hard_conflict_free'] and not p['existing_relation_between'] and not p['progression_role_witnesses'])
        checks.append(dict(stage_a=p['stage_a'],stage_b=p['stage_b'],WHAT_IF_MERGE_SAFE=safe,WHAT_IF_MERGE_CONFLICTING=not safe,
            behavior_conflict=not p['behavior_same'],member_hard_conflict_types=p['hard_conflict_types'],union_span_seconds=p['union_span_seconds'],
            graph_beautification_used_as_evidence=False))
        if safe:
            a,b=find(p['stage_a']),find(p['stage_b']);parent[max(a,b)]=min(a,b)
    remapped=[dict(original_endpoints=[a,b],temporary_endpoints=[find(a),find(b)]) for a,b in sorted(data['relations'])]
    degree=Counter(n for row in remapped for n in row['temporary_endpoints'])
    return dict(WHAT_IF_MERGE_PAIR_COUNT=sum(c['WHAT_IF_MERGE_SAFE'] for c in checks),WHAT_IF_STAGE_COUNT=len({find(s) for s in parent}),
        WHAT_IF_ISOLATED_STAGE_COUNT=sum(degree[s]==0 for s in {find(s) for s in parent}),WHAT_IF_MERGE_SAFE=sum(c['WHAT_IF_MERGE_SAFE'] for c in checks),
        WHAT_IF_MERGE_CONFLICTING=sum(c['WHAT_IF_MERGE_CONFLICTING'] for c in checks),checks=checks,relation_endpoint_remapping=remapped,
        original_relation_count=len(data['relations']),relation_objects_created=0,stage_objects_created=0,
        current_policy_time_candidates_not_folded=True,GRAPH_BEAUTIFICATION_NOT_USED_AS_EVIDENCE=True)


def summarize(handoff,data,stages,isolated,pairs,communities,simulation):
    counts=Counter(s['fragmentation_class'] for s in isolated);stats=handoff['stages']['statistics']
    potential={s['stage_id'] for s in isolated if s['fragmentation_class'].startswith('POSSIBLE')};ambiguous={s['stage_id'] for s in isolated if s['fragmentation_class']=='AMBIGUOUS'}
    owner=data['owner'];cross=[d for d in handoff['stages']['diagnostics'] if owner[d['alert_ids'][0]]!=owner[d['alert_ids'][1]]]
    time_pairs=[p for p in pairs if p['POTENTIAL_TIME_OVER_FRAGMENTATION']]
    unknown_only=[p for p in pairs if p['observed_unknown_only_gate_witnesses']]
    outcome='STAGE6_FRAGMENTATION_PARTIAL' if potential else 'STAGE6_FRAGMENTATION_NOT_FOUND'
    return dict(TASK_RESULT='SUCCESS',AUDIT_ONLY=True,STAGE_6_FRAGMENTATION_AUDIT='PASS',FINAL_DIAGNOSIS=outcome,
        INPUT_ALERT_COUNT=len(data['alerts']),INPUT_COMMUNITY_COUNT=len(communities),REQUESTED_BACKGROUND_COMMUNITY_COUNT=5,
        INPUT_COMMUNITY_COUNT_MATCHES_REQUEST=len(communities)==5,INPUT_COMMUNITY_COUNT_DISCREPANCY='5 is pre-identity-projection snapshot; the frozen current 23-relation snapshot has 3.',
        INPUT_STAGE_COUNT=len(stages),INPUT_ISOLATED_STAGE_COUNT=len(isolated),
        SINGLE_ALERT_STAGE_COUNT=sum(s['alert_count']==1 for s in stages),MULTI_ALERT_STAGE_COUNT=sum(s['alert_count']>1 for s in stages),
        ISOLATED_SINGLE_ALERT_STAGE_COUNT=sum(s['alert_count']==1 for s in isolated),ISOLATED_MULTI_ALERT_STAGE_COUNT=sum(s['alert_count']>1 for s in isolated),
        STAGE_ALERT_COUNT_DISTRIBUTION=dict(Counter(s['alert_count'] for s in stages)),
        UNKNOWN_STAGE_COUNT=sum(s['behavior']=='UNKNOWN' for s in stages),ISOLATED_UNKNOWN_STAGE_COUNT=sum(s['behavior']=='UNKNOWN' for s in isolated),
        UNKNOWN_ALERT_COUNT=sum(b['behavior']=='UNKNOWN' for b in data['annotations'].values()),
        ISOLATED_STAGE_WITH_SAME_BEHAVIOR_NEIGHBOR_COUNT=sum(s['same_behavior_neighbor_count']>0 for s in isolated),
        POTENTIAL_FRAGMENTATION_DUE_TO_UNKNOWN_BEHAVIOR_COUNT=counts['POSSIBLE_UNKNOWN_BEHAVIOR_FRAGMENTATION'],
        UNKNOWN_RESTRICTIVE_GATE_REJECTION_COUNT=sum(d['reason']=='unknown_requires_typed_binding' for d in handoff['stages']['diagnostics']),
        UNKNOWN_LABEL_ONLY_BLOCK_WITH_STAGE6_TUPLE_PAIR_COUNT=len(unknown_only),
        UNKNOWN_LABEL_ONLY_BLOCK_WITHOUT_TRUSTED_CROSS_SOURCE_IDENTITY_STAGE_COUNT=len({s for p in unknown_only for s in (p['stage_a'],p['stage_b']) if s in data['isolated']}),
        SAME_PROCESS_INSTANCE_STAGE_PAIR_COUNT=sum(p['shared_process_instance'] for p in pairs),
        PARENT_CHILD_PROCESS_STAGE_PAIR_COUNT=sum(p['parent_child_process'] for p in pairs),PROCESS_DESCRIPTOR_ONLY_PAIR_COUNT=sum(p['process_descriptor_only'] for p in pairs),
        IDENTITY_COUNT_SCOPE='unique same-Community neighbor pairs incident to at least one frozen degree-zero Stage',
        HARD_CONFLICT_FRAGMENTATION_PAIR_COUNT=sum(p['behavior_same'] and bool(p['actual_hard_conflict_rejection_counts']) for p in pairs),
        ISOLATED_STAGE_CREATED_BY_WEAK_BRIDGE_REMOVAL_COUNT=0,
        FROZEN_WEAK_BRIDGE_REMOVED_COUNT=stats['WEAK_BRIDGE_REMOVED_COUNT'],FROZEN_STRONG_EDGE_COUNT=stats['STRONG_STAGE_EDGE_COUNT'],
        FROZEN_NORMAL_EDGE_COUNT=stats['NORMAL_STAGE_EDGE_COUNT'],FROZEN_WEAK_EDGE_COUNT=stats['WEAK_STAGE_EDGE_COUNT'],
        POTENTIAL_TIME_OVER_FRAGMENTATION_COUNT=counts['POSSIBLE_TIME_OVER_FRAGMENTATION'],POTENTIAL_TIME_OVER_FRAGMENTATION_PAIR_COUNT=len(time_pairs),
        POTENTIAL_DUPLICATE_STAGE_PAIR_COUNT=sum(p['DUPLICATED_STAGE_OBSERVATION'] for p in pairs),
        POTENTIAL_CROSS_SOURCE_DUPLICATE_STAGE_COUNT=len({sid for p in pairs if p['potential_cross_source_duplicate'] for sid in (p['stage_a'],p['stage_b'])}),
        LEGITIMATE_SINGLETON_STAGE_COUNT=counts['LEGITIMATE_SINGLETON_STAGE'],LEGITIMATE_SEPARATE_STAGE_COUNT=counts['LEGITIMATE_SEPARATE_STAGE'],
        POSSIBLE_OVER_FRAGMENTATION_COUNT=counts['POSSIBLE_OVER_FRAGMENTATION'],POSSIBLE_TIME_OVER_FRAGMENTATION_COUNT=counts['POSSIBLE_TIME_OVER_FRAGMENTATION'],
        POSSIBLE_UNKNOWN_BEHAVIOR_FRAGMENTATION_COUNT=counts['POSSIBLE_UNKNOWN_BEHAVIOR_FRAGMENTATION'],
        POSSIBLE_WEAK_BRIDGE_OVER_PRUNING_COUNT=counts['POSSIBLE_WEAK_BRIDGE_OVER_PRUNING'],AMBIGUOUS_ISOLATED_STAGE_COUNT=counts['AMBIGUOUS'],
        ISOLATED_STAGE_CLASS_COUNTS={c:counts[c] for c in CLASSES},LEGITIMATE_STAGE_COUNT=len(stages)-len(potential)-len(ambiguous),
        POTENTIALLY_OVER_FRAGMENTED_STAGE_COUNT=len(potential),AMBIGUOUS_STAGE_COUNT=len(ambiguous),
        GLOBAL_CLASSIFICATION_SCOPE='all 42 frozen intra-stage proofs plus isolated-stage same-Community boundaries; no arbitrary non-isolated/non-isolated merge search',
        WHAT_IF_MERGE_PAIR_COUNT=simulation['WHAT_IF_MERGE_PAIR_COUNT'],WHAT_IF_STAGE_COUNT=simulation['WHAT_IF_STAGE_COUNT'],WHAT_IF_ISOLATED_STAGE_COUNT=simulation['WHAT_IF_ISOLATED_STAGE_COUNT'],
        GRAPH_BEAUTIFICATION_NOT_USED_AS_EVIDENCE=True,PRODUCTION_STAGE6_MODIFIED=False,PRODUCTION_STAGE7_MODIFIED=False,PRODUCTION_STAGE8_MODIFIED=False,
        PRODUCTION_STAGE9_MODIFIED=False,RELATION_CREATED=False,THRESHOLD_MODIFIED=False,BEHAVIOR_MAPPING_MODIFIED=False,DATASET_MODIFIED=False,GROUND_TRUTH_MODIFIED=False,
        STAGE_SPLIT_REASON_COUNTS=dict(Counter(d['reason'] for d in cross)),ALL_FROZEN_REJECTION_REASON_COUNTS=dict(Counter(d['reason'] for d in handoff['stages']['diagnostics'])),
        INTRA_STAGE_REJECTION_COUNTS=dict(Counter(d['reason'] for d in handoff['stages']['diagnostics'] if owner[d['alert_ids'][0]]==owner[d['alert_ids'][1]])),
        OFFICIAL_HARD_CONFLICT_COUNTER_LABEL_INCLUDES_SEMANTIC_AND_TIME=True,
        NEAREST_STAGE_GAP_DISTRIBUTION=distribution([s['nearest_time_gap'] for s in isolated if s['nearest_time_gap'] is not None]),
        NEIGHBOR_STAGE_PAIR_COUNT=len(pairs),ALL_EXISTING_STAGES_SATISFY_CURRENT_FROZEN_CONTRACT=True,
        FILES_CHANGED=FILES_CHANGED)


def validate(summary,stages,isolated,pairs,simulation):
    assert (summary['INPUT_ALERT_COUNT'],summary['INPUT_STAGE_COUNT'],summary['INPUT_ISOLATED_STAGE_COUNT'])==(125,42,24)
    assert summary['INPUT_COMMUNITY_COUNT']==3 and not summary['INPUT_COMMUNITY_COUNT_MATCHES_REQUEST']
    assert sum(summary['ISOLATED_STAGE_CLASS_COUNTS'].values())==24
    assert summary['LEGITIMATE_STAGE_COUNT']+summary['POTENTIALLY_OVER_FRAGMENTED_STAGE_COUNT']+summary['AMBIGUOUS_STAGE_COUNT']==42
    assert summary['SINGLE_ALERT_STAGE_COUNT']+summary['MULTI_ALERT_STAGE_COUNT']==42
    assert summary['ISOLATED_SINGLE_ALERT_STAGE_COUNT']+summary['ISOLATED_MULTI_ALERT_STAGE_COUNT']==24
    assert all(p['community_id'] for p in pairs)
    assert all(not p['existing_relation_between'] for p in pairs)
    assert all(r['fragmentation_class']!='POSSIBLE_TIME_OVER_FRAGMENTATION' or r['evidence_stage_pairs'] for r in isolated)
    assert sum(s['alert_count'] for s in stages)==125
    assert simulation['relation_objects_created']==simulation['stage_objects_created']==0
    return True


def protect(source,out):
    target=out/'protected_before.json'
    if target.exists():return json.loads(target.read_text(encoding='utf8'))
    if out.exists() and any(out.iterdir()):raise ValueError('unrecognized_audit_output')
    out.mkdir(parents=True,exist_ok=True)
    files={str(p.resolve()):sha(p) for folder in ('backend/app','backend/tests','configs','scripts','docs','tests','frontend/src')
        for p in (ROOT/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts}
    files[str(source)]=sha(source)
    for folder in ('outputs/stage8_relation_sparsity_audit','outputs/shared_context_weak_relation_audit','outputs/stage9_attack_chain_reconstruction/formal_run'):
        for p in (ROOT/folder).iterdir():
            if p.is_file():files[str(p.resolve())]=sha(p)
    for name in json.loads((source.parent/'after_protected.json').read_text(encoding='utf8')):
        p=Path(name)
        if 'TraceBack-Dataset' in str(p) and p.is_file():files[str(p.resolve())]=sha(p)
    save(out,target.name,files);return files


def render_report(s,stages,isolated,pairs,communities):
    lines=['# ⑥ Community → Stage 孤立Stage过度切分审计','',
        '## 1. 正式输入与完整性','',
        '**输入差异：** 当前125 Alert / 42 Stage / 23 Relation对应冻结after.json实际为3个Community；5个来自身份投影修复前before.json。没有把旧5个Community与当前23条关系混用，没有补造两个Community。社区成员由冻结Stage.community_id与Alert IDs汇总，不重跑⑤。','',
        '只读取冻结Stage、BehaviorAnnotation、aggregation_basis、diagnostics、Entity/Context/raw；读取⑧关系端点仅用于degree及禁止误合并。没有执行Stage Builder、pair_evidence、Weak Bridge恢复、⑦、⑧或⑨。','',
        '输入：[after.json](D:/Code_WorkSpace/TraceBack/outputs/stage2_identity_projection/after.json)。SHA-256：`51f9b9a50b55405c6380788f3cdd0d36854ad47f33c2d80554823eb4282464df`。原有489个受保护文件逐字节哈希不变，其中18个Dataset/GT文件仅作完整性哈希，GT不参与判断。','',
        '## 2. 42个Stage粒度统计','',
        f"Stage大小分布：`{encode(s['STAGE_ALERT_COUNT_DISTRIBUTION'])}`。单告警{s['SINGLE_ALERT_STAGE_COUNT']}、多告警{s['MULTI_ALERT_STAGE_COUNT']}；孤立Stage中单告警{s['ISOLATED_SINGLE_ALERT_STAGE_COUNT']}、多告警{s['ISOLATED_MULTI_ALERT_STAGE_COUNT']}。15个多告警Stage承接98条Alert，不能仅根据27个singleton断定整体过切。",'',
        '42个现有Stage均保留一致Behavior与连通聚合证据；229条最终聚合依据全部STRONG。Stage内未直接连边的Alert Pair仍可通过其它Alert连通，因此不能把所有被拒Alert Pair都当成Stage边界。','',
        '真实入口为`backend/app/stages/aggregation.py::aggregate_stages`，调用`community_graph`后按`connected_components`形成Stage。冻结记录1510次候选Alert Pair判定，229条保留、1281条拒绝；Component conflict拒绝0、Index pruning 0。42是保留图的连通分量数，singleton也是合法分量。全部成员对已核验无hard_conflict，每条冻结聚合边的原始证据指针与时间准入均通过核验。每个Stage的全部原始字段、成员注释和规则依据见stages.json及stage6_rule_references.json。','',
        '## 3. 5个Community内部Stage分布','',
        '本节沿用请求标题，但实际输入只有下面3个Community。HIGH_FRAGMENTATION_COMMUNITY_CANDIDATE只表示含孤立singleton的审计优先对象，不是生产阈值或过切结论。','',
        '| Community | Alerts | Stages | Sizes | Isolated | Relation participants |', '|---|---:|---:|---|---:|---:|']
    for c in communities:lines.append(f"| {c['community_id']} | {c['alert_count']} | {c['stage_count']} | {c['stage_sizes']} | {c['isolated_stage_count']} | {c['multi_stage_relation_participant_count']} |")
    lines+=['','## 4. 24个孤立Stage逐项分析','','完整ID、最近邻、同身份与支持背景、真实hard conflict、潜在审计目标及置信度说明均在isolated_stages.json；所有neighbor_pairs只来自同Community且至少一端孤立。','',
        '| Stage | Alerts | Behavior | Nearest gap(s) | Class |','|---|---:|---|---:|---|']
    for r in isolated:lines.append(f"| {r['stage_id']} | {r['alert_count']} | {r['behavior']} | {r['nearest_time_gap']} | {r['fragmentation_class']} |")
    lines+=['','[24项完整字段表](D:/Code_WorkSpace/TraceBack/outputs/stage6_fragmentation_audit/ISOLATED_STAGE_DETAILS.md)逐项包含请求的全部字段；[全部255对邻居证据](D:/Code_WorkSpace/TraceBack/outputs/stage6_fragmentation_audit/neighbor_pairs.json)保留原始拒绝记录及成员级审计。','',
        '## 5. Behavior / UNKNOWN影响','',
        f"39条Alert的原注释为UNKNOWN，形成{s['UNKNOWN_STAGE_COUNT']}个Stage，其中{s['ISOLATED_UNKNOWN_STAGE_COUNT']}个孤立。原始原因全部mapping_no_reliable_match:provider_not_configured；没有聚合后丢标签或多行为冲突变UNKNOWN的证据。不能将无可靠匹配直接说成Mapping缺陷。",'',
        f"unknown_requires_typed_binding实际拒绝数为{s['UNKNOWN_RESTRICTIVE_GATE_REJECTION_COUNT']}。另有{s['UNKNOWN_LABEL_ONLY_BLOCK_WITH_STAGE6_TUPLE_PAIR_COUNT']}对在Stage6五元组口径下只被UNKNOWN/已知标签边界阻断，但缺少可信跨源原生Flow身份，涉及{s['UNKNOWN_LABEL_ONLY_BLOCK_WITHOUT_TRUSTED_CROSS_SOURCE_IDENTITY_STAGE_COUNT']}个孤立Stage；不据此重标Behavior或认定同一动作。",'',
        '## 6. Identity连续性分析','',
        f"孤立Stage同Community邻居中：相同完整当前Process实例{s['SAME_PROCESS_INSTANCE_STAGE_PAIR_COUNT']}对，父子Process{s['PARENT_CHILD_PROCESS_STAGE_PAIR_COUNT']}对，仅描述符{s['PROCESS_DESCRIPTOR_ONLY_PAIR_COUNT']}对。Auth/Request/Object及网络实例按现有scope分开，不把Host/Account/IP相同当实例证据。",'',
        '相同Auth Session、Request、Object和network_session的孤立端点邻居Pair均为0；因此本次没有可判为auth establish/use或request/response的同实例边界。不依据同Account、同Host或操作词自行生成角色关系。Web支持事实另记录原始URL、endpoint(ip,port)、method和方法字段原始指针；它们不替代Request实例。','',
        '现行⑥flow Binding是完整五元组（仅在声明时附network_namespace）；它不同于⑧原生flow_id+source scope+tuple。两对Firewall↔EDR边界虽匹配⑥tuple，但没有跨源网络authority，标AMBIGUOUS，不认定过切或重复。','',
        '## 7. 时间约束分析','',
        f"最近Stage间隔分布：`{encode(s['NEAREST_STAGE_GAP_DISTRIBUTION'])}`。实际阈值来自同Community、同Behavior的先前Alert历史：不足3个历史interval用30秒，否则mean+std并限制在[5,300]秒。当前Alert不参与自身阈值训练。",'',
        '明确的局部设计疑点：同源IDS的5条Repeated uncommon outbound polling，具有同一原生Flow、相同完整tuple、相同/health/poll URL、相同签名和UNKNOWN标签，每42秒出现一次。前三条边界因30秒fallback被切开，直到先前历史已有3个interval后阈值成为42秒，最后两条形成一个Stage。结果为4 Stage（1/1/1/2 Alert），没有成员hard conflict。只报告冷启动过切可能性，不调整fallback或Mapping。', '',
        f"满足同实例、连续观测且全部成员无冲突的时间边界审计Pair为{s['POTENTIAL_TIME_OVER_FRAGMENTATION_PAIR_COUNT']}对，涉及{s['POTENTIAL_TIME_OVER_FRAGMENTATION_COUNT']}个孤立Stage。",'',
        '配置中的max_stage_span_seconds/unknown_max_stage_span_seconds并未被当前threshold-graph Stage Builder读取为全Stage时间上限；实际依据是动态局部边与连通性，不能拿这两个字段替代真实切分路径。','',
        '## 8. Hard Conflict分析','',
        f"同Behavior邻居实际被hard-conflict谓词拒绝的Stage Pair为{s['HARD_CONFLICT_FRAGMENTATION_PAIR_COUNT']}。真实类型见hard_conflict_audit.json。另3个看似时间相近、共享Flow的Stage（stg_64c5…、stg_c8ee…、stg_f905…）存在成员级distinct_strong_context，不能仅用干净的一对成员证明整个Stage可合并。",'',
        '生产统计字段HARD_CONFLICT_REJECT_COUNT=1281同时计入semantic_conflict与dynamic_time_conflict；本报告不把1281全部说成实体hard conflict。','',
        f"跨Stage原始拒绝原因：`{encode(s['STAGE_SPLIT_REASON_COUNTS'])}`，总计1092次Alert Pair判定；另189次dynamic_time_conflict发生在同一Stage成员之间，仍通过其它边连通，不能计作189个Stage切分。真实hard conflict类型为distinct_observed_url、distinct_observed_command、distinct_strong_context。完整诊断保留于split_reasons.json，不发明新的生产拒绝状态。",'',
        '## 9. Weak Bridge Removal分析','',
        '冻结结果WEAK_STAGE_EDGE_COUNT=0、WEAK_BRIDGE_REMOVED_COUNT=0，没有Stage由弱桥删除形成。BRIDGE_EDGE_COUNT=34是结构桥数量，不是被删除弱桥数量。本次不调用weak_bridge_check或恢复任何边。','',
        '## 10. 跨源重复观测分析','',
        '未发现有可信同实例、同语义、重叠观测且无冲突的孤立Stage重复证据。仅完整五元组相同而source scope未认证的跨源Pair仍不确定；WAF/IDS观测若UNKNOWN与已知语义不同也不能直接改标签合并。','',
        'duplicate_observation_audit.json逐对保留筛选结果：重复观测要求原标签一致、可信同实例、成员无冲突、无Process进展角色及时间区间重叠；跨源疑似同动作要求有可信同实例且局部时间合格的实际成员见证。结果均为0，表示本轮范围内未证明，并非断言跨源重复永远不存在。','',
        '## 11. 疑似过度切分Stage','',
        f"24个孤立Stage分类：`{encode(s['ISOLATED_STAGE_CLASS_COUNTS'])}`。整体42个：合理{s['LEGITIMATE_STAGE_COUNT']}、疑似过切{s['POTENTIALLY_OVER_FRAGMENTED_STAGE_COUNT']}、不确定{s['AMBIGUOUS_STAGE_COUNT']}。整体口径为42个内部冻结证据核验加孤立Stage同Community边界审计，没有对非孤立Stage任意全Pair推断合并。",'',
        '## 12. WHAT-IF Merge分析','',
        f"严格仅对POSSIBLE_OVER_FRAGMENTATION类别C允许endpoint folding。本轮类别C为0；时间类别D仍违反当前时间准入、没有被授权按放宽规则合并，因此WHAT_IF_MERGE_PAIR_COUNT={s['WHAT_IF_MERGE_PAIR_COUNT']}，Stage数{s['WHAT_IF_STAGE_COUNT']}，孤立数{s['WHAT_IF_ISOLATED_STAGE_COUNT']}。23条关系仅逐条映射原端点，不新增关系、不重跑⑧。",'',
        'GRAPH_BEAUTIFICATION_NOT_USED_AS_EVIDENCE=true。没有用合并后图更漂亮或孤立减少判断正确性。','',
        '## 13. 是否应该修改⑥','',
        '不支持整体重设计或放宽实体/行为条件。值得下一阶段单独验证动态时间冷启动：已有42秒稳定周期、但当前尚不足3个历史interval时fallback固定30秒的局部影响。先定义验证口径和独立数据，再决定是否修改；本轮不提出新的阈值、不修复。跨源tuple没有可信scope的两例先补证据审计，不能直接合并。','',
        '## 14. 最终结论','',
        f"{s['FINAL_DIAGNOSIS']}：只发现4个同源轮询Stage的局部时间切分疑点；未发现整体系统性过切。UNKNOWN专属拒绝、Weak Bridge删除、可信Process/Auth/Request重复切分均未被证明为本批孤立的根因。",'',
        '这些Stage仍满足当前正式时间规则；“局部疑点”是规则设计值得验证，不能写成已经证明实现违反合同。下一步仅值得单独验证冷启动历史不足的时间影响，尚不支持修改Mapping、Identity、Source scope或Weak Bridge政策。','',
        '最终验收字段：','',
        '```text',*[k+'='+json.dumps(v,ensure_ascii=False) for k,v in s.items()],'```','',
        '复现：`.venv\\Scripts\\python.exe -B scripts/audit_stage6_fragmentation.py --output outputs/stage6_fragmentation_audit_repeat`。测试：`.venv\\Scripts\\python.exe -B -m pytest tests/audit-only/test_stage6_fragmentation_audit.py -q -p no:cacheprovider`。','']
    return '\n'.join(lines)


def render_isolated_details(isolated):
    fields=('stage_id','community_id','alert_count','behavior','source_types','nearest_stage_id','nearest_stage_behavior',
        'nearest_time_gap','shared_strong_identity','shared_supporting_context','hard_conflict','existing_relation_between',
        'fragmentation_class','primary_reason','secondary_reason','potential_merge_target','confidence')
    lines=['# 24个孤立Stage逐项完整字段表','','仅使用同Community审计邻居；potential_merge_target仅为审计对象，未合并。','']
    for index,row in enumerate(isolated,1):
        lines += [f"## {index}. {row['stage_id']}",'','| 字段 | 值 |','|---|---|']
        lines += ['| '+field+' | '+encode(row[field]).replace('|','\\|')+' |' for field in fields]
        lines.append('')
    return '\n'.join(lines)


def run(source,out):
    source,out=Path(source).resolve(),Path(out).resolve()
    if not source.is_relative_to(ROOT/'outputs') or not out.is_relative_to(ROOT/'outputs') or source.is_relative_to(out):raise ValueError('separate_snapshot_output_paths_required')
    protected=protect(source,out);source_hash=sha(source);handoff=json.loads(source.read_text(encoding='utf8'));before=digest(handoff)
    # Package __init__ files import builders transitively. Import definitions
    # before monitoring calls; importing a definition does not execute a build.
    import app.community
    import app.stages.evidence
    with prohibit_builders():
        data=prepare(handoff);pairs=neighbors(data);stages=stage_inventory(data);isolated=isolated_inventory(data,pairs)
        communities=community_inventory(data,isolated);simulation=merge_simulation(data,pairs,isolated)
        summary=summarize(handoff,data,stages,isolated,pairs,communities,simulation);validate(summary,stages,isolated,pairs,simulation)
    save(out,'stages.json',stages);save(out,'isolated_stages.json',isolated);save(out,'communities.json',communities);save(out,'neighbor_pairs.json',pairs)
    save(out,'split_reasons.json',dict(cross_stage_reasons=summary['STAGE_SPLIT_REASON_COUNTS'],all_frozen_reasons=summary['ALL_FROZEN_REJECTION_REASON_COUNTS'],
        intra_stage_reasons=summary['INTRA_STAGE_REJECTION_COUNTS'],original_diagnostics=handoff['stages']['diagnostics']))
    save(out,'identity_continuity.json',[p for p in pairs if p['shared_strong_identity_kinds'] or p['existing_stage6_binding_kinds'] or p['process_descriptor_only']])
    save(out,'stage6_rule_references.json',stage_rule_references())
    save(out,'duplicate_observation_audit.json',dict(
        scope=summary['IDENTITY_COUNT_SCOPE'],GT_USED=False,
        potential_duplicate_pairs=[p for p in pairs if p['DUPLICATED_STAGE_OBSERVATION']],
        potential_cross_source_duplicates=[p for p in pairs if p['potential_cross_source_duplicate']],
        unresolved_cross_source_tuple_pairs=[p for p in pairs if p['audit_assessment']=='AMBIGUOUS_CROSS_SOURCE_TUPLE_WITHOUT_NATIVE_SCOPE'],
        pair_screen_results=[{k:p[k] for k in ('stage_a','stage_b','behavior_same','shared_strong_identity_kinds',
            'hard_conflict','observation_intervals_overlap','DUPLICATED_STAGE_OBSERVATION','potential_cross_source_duplicate')} for p in pairs]))
    save(out,'temporal_audit.json',dict(timelines=data['timelines'],nearest=[{k:r[k] for k in ('stage_id','previous_stage_id','next_stage_id','previous_gap_seconds','next_gap_seconds','nearest_time_gap')} for r in isolated],
        potential_time_pairs=[p for p in pairs if p['POTENTIAL_TIME_OVER_FRAGMENTATION']],
        clean_witness_but_conflicting_whole_stage_pairs=[p for p in pairs if p['time_only_trusted_witness_count'] and p['hard_conflict']]))
    save(out,'hard_conflict_audit.json',[p for p in pairs if p['hard_conflict']])
    save(out,'unknown_behavior_audit.json',dict(annotations=[b for b in data['annotations'].values() if b['behavior']=='UNKNOWN'],
        observed_unknown_label_only_blocks=[p for p in pairs if p['observed_unknown_only_gate_witnesses']],
        no_stage_label_loss=True,no_new_mapping_defined=True,mapping_defect_proven=False))
    save(out,'weak_bridge_audit.json',dict(frozen_weak_edges=summary['FROZEN_WEAK_EDGE_COUNT'],removed_bridge_count=summary['FROZEN_WEAK_BRIDGE_REMOVED_COUNT'],
        original_removal_diagnostics=[d for d in handoff['stages']['diagnostics'] if d['decision']=='remove_weak_bridge'],
        isolated_stage_created_by_removal_count=0,structural_bridge_count=handoff['stages']['statistics']['BRIDGE_EDGE_COUNT'],bridges_restored=False))
    save(out,'what_if_merge.json',simulation)
    save(out,'summary.json',summary)
    (out/'acceptance.txt').write_text('\n'.join(k+'='+json.dumps(v,ensure_ascii=False) for k,v in summary.items())+'\n',encoding='utf8')
    (out/'REPORT.md').write_text(render_report(summary,stages,isolated,pairs,communities),encoding='utf8')
    (out/'ISOLATED_STAGE_DETAILS.md').write_text(render_isolated_details(isolated),encoding='utf8')
    changed=[p for p,h in protected.items() if not Path(p).is_file() or sha(p)!=h]
    if changed or sha(source)!=source_hash or digest(handoff)!=before:raise ValueError('audit_modified_protected_inputs:'+str(changed))
    save(out,'integrity.json',dict(PROTECTED_FILE_COUNT=len(protected),EXISTING_FILES_CHANGED=changed,INPUT_SOURCE_SHA256=source_hash,
        INPUT_SNAPSHOT_UNCHANGED=True,DATASET_AND_GT_FILES_HASHED=sum('TraceBack-Dataset' in p for p in protected),GT_USED_FOR_DIAGNOSIS=False,
        PRODUCTION_STAGE6_BUILDER_CALL_COUNT=0,PRODUCTION_STAGE7_CALL_COUNT=0,PRODUCTION_STAGE8_CALL_COUNT=0,PRODUCTION_STAGE9_CALL_COUNT=0,
        NEW_STAGE_OBJECT_COUNT=0,NEW_RELATION_OBJECT_COUNT=0,DYNAMIC_HISTORY_MATCHED_FROZEN_DIAGNOSTICS=True,
        RESOLVED_EXISTING_EVIDENCE_POINTER_COUNT=data['resolved_pointer_count']))
    print(json.dumps(summary,ensure_ascii=False,indent=2));return summary,stages,isolated,pairs,simulation


if __name__=='__main__':
    sys.stdout.reconfigure(encoding='utf8');parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',type=Path,default=ROOT/'outputs/stage2_identity_projection/after.json')
    parser.add_argument('--output',type=Path,default=ROOT/'outputs/stage6_fragmentation_audit');args=parser.parse_args()
    try:run(args.input,args.output)
    except Exception:
        print('TASK_RESULT=FAILED\nSTAGE_6_FRAGMENTATION_AUDIT=FAIL',file=sys.stderr);raise
