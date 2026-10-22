"""Read-only ⑧ quality audit. Diagnostic sets only; never a production ⑨ graph.

All new files are confined to --output. Production code/config/data are hashed
before running the official entry. GT is read only after that entry returns.
"""
import argparse
from collections import Counter, defaultdict
from dataclasses import asdict
import hashlib
from itertools import combinations
import json
import math
import os
from pathlib import Path
import statistics
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'backend'))
sys.dont_write_bytecode = True
DATA = Path('D:/Code_WorkSpace/TraceBack-Dataset/data/attack125')
ACTIVE = False
CALLS = Counter()
READS = set()


def encode(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))


def digest(value):
    return hashlib.sha256(encode(value).encode('utf8')).hexdigest()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(out,name,value):
    (out/name).write_text(json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2)+'\n',encoding='utf8')


def inventory(dataset):
    return {str(p.resolve()):sha(p) for folder in (ROOT/'backend/app',ROOT/'backend/tests',ROOT/'configs',ROOT/'frontend/src',dataset)
        for p in folder.rglob('*') if p.is_file() and '__pycache__' not in p.parts}


def protect(args):
    args.output.mkdir(parents=True,exist_ok=True)
    path = args.output/'protected_before.json'
    if not path.exists():
        save(args.output,path.name,inventory(args.dataset_root))
    return json.loads(path.read_text(encoding='utf8'))


def audit_io(event,args):
    if not ACTIVE:
        return
    if event == 'socket.connect':
        raise AssertionError('production_network_forbidden')
    if event == 'open' and not isinstance(args[0],int):
        path = Path(os.fsdecode(args[0])).resolve()
        if args[2] & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):
            raise AssertionError('production_write_forbidden:'+str(path))
        if {'outputs','evaluation','ground_truth'} & {part.casefold() for part in path.parts}:
            raise AssertionError('production_snapshot_or_gt_read_forbidden:'+str(path))
        if path.suffix.lower() not in {'.py','.pyc','.pyd','.dll'}:
            READS.add(str(path))


def profile_calls(frame,event,arg):
    if event != 'call':
        return
    module,name = frame.f_globals.get('__name__',''),frame.f_code.co_name
    if module.startswith(('app.stage_relations','app.correlation','app.stage_chains','app.chains','app.api','app.ai','evaluation')):
        raise AssertionError('legacy_or_downstream_execution_forbidden:'+module+'.'+name)
    if module.startswith('app.') and name in {'load_stage_pipeline','load_alert_pipeline','extract_entities','filter_alerts',
            'normalize_behaviors','build_communities','aggregate_stages','generate_stage_pair_candidates','validate_stage_pair_candidates'}:
        CALLS[module+'.'+name] += 1


def quantile(values,p):
    """Linear interpolation at (n-1)*p, including isolated nodes and zero counts."""
    if not values:
        return 0.0
    values = sorted(values)
    position = (len(values)-1)*p
    lo,hi = math.floor(position),math.ceil(position)
    return values[lo]+(values[hi]-values[lo])*(position-lo)


def distribution(values):
    return dict(min=min(values) if values else 0,median=statistics.median(values) if values else 0,
        p90=quantile(values,.9),max=max(values) if values else 0)


def components(nodes,pairs):
    neighbors = {n:set() for n in nodes}
    for a,b in pairs:
        neighbors[a].add(b)
        neighbors[b].add(a)
    pending,result = set(nodes),[]
    while pending:
        seen,stack = set(),[min(pending)]
        while stack:
            node = stack.pop()
            if node not in seen:
                seen.add(node)
                stack.extend(neighbors[node]-seen)
        result.append(sorted(seen))
        pending -= seen
    return sorted(result,key=lambda group:(-len(group),group)),neighbors


def alternate_path(pairs,pair):
    nodes = {x for p in pairs for x in p}
    remaining = set(pairs)-{pair}
    groups,_ = components(nodes,remaining)
    return any(set(pair) <= set(group) for group in groups)


def graph_statistics(nodes,decisions):
    edges = [d for d in decisions if d.relation_type != 'NO_RELATION']
    pairs = {(d.stage_a_id,d.stage_b_id) for d in edges}
    groups,neighbors = components(nodes,pairs)
    degrees = [len(neighbors[n]) for n in nodes]
    outdegree = Counter(d.from_stage_id for d in edges if d.relation_type == 'DIRECTED_EDGE')
    indegree = Counter(d.to_stage_id for d in edges if d.relation_type == 'DIRECTED_EDGE')
    return dict(NODE_COUNT=len(nodes),RELATION_EDGE_COUNT=len(pairs),GRAPH_DENSITY=len(pairs)/(math.comb(len(nodes),2) or 1),
        AVERAGE_DEGREE=sum(degrees)/(len(nodes) or 1),MAX_DEGREE=max(degrees,default=0),
        MEDIAN_DEGREE=statistics.median(degrees) if degrees else 0,P90_DEGREE=quantile(degrees,.9),
        ISOLATED_STAGE_COUNT=sum(d == 0 for d in degrees),CONNECTED_COMPONENT_COUNT=len(groups),
        LARGEST_COMPONENT_SIZE=max(map(len,groups),default=0),DIRECTED_OUT_DEGREE_MAX=max(outdegree.values(),default=0),
        DIRECTED_IN_DEGREE_MAX=max(indegree.values(),default=0),degree_by_stage={n:len(neighbors[n]) for n in sorted(nodes)},
        diagnostic_components=groups)


def claim_key(evidence):
    # Different Alert pairs, raw pointer paths and repeated observations do not
    # create new Stage-level claims. Direction/semantic roles remain distinct.
    return (evidence.stage_a_id,evidence.stage_b_id,evidence.evidence_type,
        encode(evidence.metadata['identity']),evidence.direction_claim,
        evidence.metadata.get('role_a'),evidence.metadata.get('role_b'))


def identity_key(evidence):
    return evidence.evidence_type,encode(evidence.metadata['identity'])


def associative_audit(run,ss,aa):
    result = run.evidence_result
    decisions = {(d.stage_a_id,d.stage_b_id):d for d in result.decisions}
    identities = defaultdict(list)
    claims = defaultdict(list)
    by_pair = defaultdict(list)
    for e in result.evidence:
        claims[claim_key(e)].append(e)
        by_pair[(e.stage_a_id,e.stage_b_id)].append(e)
        if e.valid and e.evidence_strength_class == 'ASSOCIATIVE_STRONG':
            identities[identity_key(e)].append(e)
    rows,redundant = [],set()
    redundant_by_type = defaultdict(set)
    for (kind,identity),witnesses in identities.items():
        stages = {sid for e in witnesses for sid in (e.stage_a_id,e.stage_b_id)}
        alerts = {aid for e in witnesses for aid in (e.alert_a_id,e.alert_b_id)}
        pairs = {(e.stage_a_id,e.stage_b_id) for e in witnesses}
        undirected = {p for p in pairs if decisions[p].relation_type == 'UNDIRECTED_EDGE'}
        alternate = {p for p in undirected if alternate_path(undirected,p)}
        redundant.update(alternate)
        redundant_by_type[kind].update(alternate)
        times = [aa[aid].timestamp for aid in alerts]
        from app.community.evidence import seconds
        theoretical = math.comb(len(stages),2)
        rows.append(dict(identity_type=kind,identity_hash=digest(dict(kind=kind,identity=identity)),identity=json.loads(identity),
            stage_count=len(stages),relation_pair_count=len(pairs),undirected_relation_pair_count=len(undirected),
            theoretical_pair_count=theoretical,pairwise_coverage=len(pairs)/(theoretical or 1),
            associative_identity_clique=len(stages)>=3 and len(pairs)==theoretical,
            entirely_undirected_clique=len(stages)>=3 and len(undirected)==theoretical,
            stage_ids=sorted(stages),relation_pairs=[list(p) for p in sorted(pairs)],undirected_relation_pairs=[list(p) for p in sorted(undirected)],
            communities_covered=sorted({ss[sid].community_id for sid in stages}),alerts_covered=len(alerts),alert_ids=sorted(alerts),
            time_span=dict(start=min(times),end=max(times),seconds=seconds(max(times))-seconds(min(times))),
            source_namespaces=sorted({aa[aid].source_namespace for aid in alerts}),raw_witness_count=len(witnesses),
            unique_claim_count=len({claim_key(e) for e in witnesses}),potentially_redundant_pairs=[list(p) for p in sorted(alternate)],
            behaviors=dict(Counter(ss[sid].behavior for sid in stages))))
    rows.sort(key=lambda row:(-row['stage_count'],-row['relation_pair_count'],row['identity_hash']))
    primary = defaultdict(list)
    ee = {e.evidence_id:e for e in result.evidence}
    for d in result.decisions:
        if d.relation_type == 'UNDIRECTED_EDGE':
            primary[ee[d.primary_evidence_id].evidence_type].append(ee[d.primary_evidence_id])
    types = sorted(set(primary)|{'SAME_SCOPED_FLOW','SAME_PROCESS_INSTANCE','SAME_STRONG_SESSION','SAME_SCOPED_REQUEST','SAME_SCOPED_OBJECT'})
    attribution = {}
    for kind in types:
        items = primary[kind]
        counts = Counter(identity_key(e) for e in items)
        attribution[kind] = dict(RELATION_COUNT=len(items),UNIQUE_IDENTITY_COUNT=len(counts),
            AVG_RELATIONS_PER_IDENTITY=len(items)/(len(counts) or 1),MAX_RELATIONS_PER_IDENTITY=max(counts.values(),default=0))
    pair_rows = []
    for pair,candidate in sorted((( (c.stage_a_id,c.stage_b_id),c) for c in run.candidates)):
        witnesses = by_pair[pair]
        distinct = {claim_key(e) for e in witnesses}
        pair_rows.append(dict(stage_a_id=pair[0],stage_b_id=pair[1],relation_type=decisions[pair].relation_type,
            raw_witness_count=len(witnesses),unique_evidence_claim_count=len(distinct),logically_duplicate_witness_count=len(witnesses)-len(distinct),
            stage_alert_counts=[ss[sid].alert_count for sid in pair],evidence_type_counts=dict(Counter(e.evidence_type for e in witnesses)),
            candidate_reasons=candidate.candidate_reasons))
    pair_rows.sort(key=lambda row:(-row['raw_witness_count'],row['stage_a_id'],row['stage_b_id']))
    repeated = []
    for key,witnesses in claims.items():
        if len(witnesses)<=1:
            continue
        left={e.alert_a_id for e in witnesses}
        right={e.alert_b_id for e in witnesses}
        repeated.append(dict(stage_a_id=key[0],stage_b_id=key[1],evidence_type=key[2],identity=json.loads(key[3]),
            direction_claim=key[4],roles=[key[5],key[6]],raw_witness_count=len(witnesses),
            distinct_alert_pair_count=len({(e.alert_a_id,e.alert_b_id) for e in witnesses}),
            left_alert_count=len(left),right_alert_count=len(right),cartesian_product_size=len(left)*len(right),
            complete_cartesian_product=len(witnesses)==len(left)*len(right),evidence_ids=[e.evidence_id for e in witnesses]))
    repeated.sort(key=lambda row:(-row['raw_witness_count'],row['evidence_type'],row['stage_a_id']))
    return dict(identity_postings=rows,primary_attribution=attribution,redundant_pairs=sorted(redundant),
        redundant_by_evidence_type={k:len(v) for k,v in sorted(redundant_by_type.items())},pair_witness_counts=pair_rows,
        repeated_claims=repeated,unique_claim_count=len(claims),raw_witness_count=len(result.evidence),
        logically_duplicate_count=len(result.evidence)-len(claims))


def community_source_time_audit(run,ss,aa):
    from app.community.evidence import seconds
    ee = {e.evidence_id:e for e in run.evidence_result.evidence}
    flags = Counter()
    primary_sources,all_sources = defaultdict(Counter),defaultdict(Counter)
    gaps = defaultdict(list)
    witness_gaps = defaultdict(list)
    communities = []
    for d in run.evidence_result.decisions:
        if d.relation_type == 'NO_RELATION':
            continue
        a,b = ss[d.stage_a_id],ss[d.stage_b_id]
        scope = 'SAME_COMMUNITY' if a.community_id == b.community_id else 'CROSS_COMMUNITY'
        flags[scope+('_DIRECTED' if d.relation_type == 'DIRECTED_EDGE' else '_UNDIRECTED')] += 1
        e=ee[d.primary_evidence_id]
        key=' ↔ '.join(sorted([aa[e.alert_a_id].source_namespace,aa[e.alert_b_id].source_namespace]))
        primary_sources[d.relation_type][key] += 1
        seen=set()
        for eid in [d.primary_evidence_id,*d.supporting_evidence_ids]:
            w=ee[eid]
            if w.valid and w.evidence_strength_class != 'SUPPORTING_ONLY':
                seen.add(' ↔ '.join(sorted([aa[w.alert_a_id].source_namespace,aa[w.alert_b_id].source_namespace])))
        all_sources[d.relation_type].update(seen)
        gaps[d.relation_type].append(max(0,seconds(max(a.start_time,b.start_time))-seconds(min(a.end_time,b.end_time))))
        witness_gaps[d.relation_type].append(abs(seconds(aa[e.alert_a_id].timestamp)-seconds(aa[e.alert_b_id].timestamp)))
    for cid in sorted({s.community_id for s in ss.values()}):
        stages=[s.stage_id for s in ss.values() if s.community_id==cid]
        internal=[d for d in run.evidence_result.decisions if d.relation_type!='NO_RELATION' and {d.stage_a_id,d.stage_b_id} <= set(stages)]
        counts=Counter(d.relation_type for d in internal)
        communities.append(dict(community_id=cid,stage_count=len(stages),relation_count=len(internal),
            density=len(internal)/(math.comb(len(stages),2) or 1),directed_count=counts['DIRECTED_EDGE'],undirected_count=counts['UNDIRECTED_EDGE']))
    communities.sort(key=lambda row:(-row['density'],-row['stage_count'],row['community_id']))
    return dict(community_counts={k:flags[k] for k in ('SAME_COMMUNITY_DIRECTED','SAME_COMMUNITY_UNDIRECTED','CROSS_COMMUNITY_DIRECTED','CROSS_COMMUNITY_UNDIRECTED')},
        communities=communities,source_pairs_primary={k:dict(v) for k,v in primary_sources.items()},
        source_pairs_any_valid_strong_witness={k:dict(v) for k,v in all_sources.items()},
        stage_interval_gap_seconds={k:distribution(v) for k,v in gaps.items()},
        primary_witness_timestamp_gap_seconds={k:distribution(v) for k,v in witness_gaps.items()})


def xml_counts(paths):
    counts=Counter()
    for path in paths:
        root=ET.parse(path).getroot()
        for suite in (list(root) if root.tag=='testsuites' else [root]):
            for key in ('tests','failures','errors','skipped'):
                counts[key]+=int(suite.attrib.get(key,0))
    return dict(passed=counts['tests']-counts['failures']-counts['errors']-counts['skipped'],
        failed=counts['failures'],errors=counts['errors'],skipped=counts['skipped'])


def verify(args):
    global ACTIVE
    before=protect(args)
    from app.services.stage_pipeline import load_stage_pipeline
    sys.addaudithook(audit_io)
    ACTIVE=True
    sys.setprofile(profile_calls)
    try:
        run=load_stage_pipeline(args.input)
    finally:
        sys.setprofile(None)
        ACTIVE=False
    aa={a.alert_id:a for a in run.community.alerts}
    ss={s.stage_id:s for s in run.stages.stages}
    ee={e.entity_id:e for e in run.community.entities}
    result=run.evidence_result
    expected=dict(INPUT_ALERTS=125,INPUT_STAGE_COUNT=42,INPUT_CANDIDATE_PAIR_COUNT=165,
        DIRECTED_EDGE_COUNT=12,UNDIRECTED_EDGE_COUNT=139,NO_RELATION_COUNT=14)
    assert all(result.statistics[k]==v for k,v in expected.items())
    assert sum(expected[k] for k in ('DIRECTED_EDGE_COUNT','UNDIRECTED_EDGE_COUNT','NO_RELATION_COUNT'))==len(run.candidates)
    assert all(n==1 for n in CALLS.values()) and len(CALLS)==9,CALLS
    current_result=result.model_dump(mode='json')
    old_path=ROOT/'outputs/stage8_evidence_verification/evidence_result.json'
    identical=current_result==json.loads(old_path.read_text(encoding='utf8')) if old_path.exists() else None
    assert identical is not False,'official_version_or_output_changed'
    save(args.output,'current_official_result.json',current_result)
    save(args.output,'current_official_inputs.json',dict(alerts=[a.model_dump(mode='json') for a in aa.values()],
        entities=[e.model_dump(mode='json') for e in ee.values()],stages=run.stages.model_dump(mode='json'),
        communities=run.community.result.model_dump(mode='json'),candidates=run.candidate_result.model_dump(mode='json'),
        source_settings={k:asdict(v) for k,v in run.normalized.source_settings.items()}))
    graph=graph_statistics(sorted(ss),result.decisions)
    associative=associative_audit(run,ss,aa)
    context=community_source_time_audit(run,ss,aa)
    save(args.output,'density.json',graph)
    save(args.output,'identity_postings.json',associative['identity_postings'])
    save(args.output,'witness_expansion.json',{k:v for k,v in associative.items() if k!='identity_postings'})
    save(args.output,'community_source_time.json',context)
    # GT-root-cause analysis and human-readable findings are appended below.
    finalize(args,run,aa,ss,ee,before,identical,graph,associative,context)


def code_ref(path,needle):
    lines=(ROOT/path).read_text(encoding='utf8').splitlines()
    line=next(i for i,text in enumerate(lines,1) if needle in text)
    return dict(path=str((ROOT/path).resolve()),line=line,text=lines[line-1].strip())


def gt_audit(args,run,aa,ss,entities):
    from app.community import load_community_config
    from app.community.evidence import profile
    from app.stage_evidence import load_evidence_config
    from app.stage_evidence.extraction import project_witnesses
    from app.models.alerts import EvidencePointer
    from app.utils.stable_id import content_digest
    config=load_community_config(ROOT/'configs/community-v1.yaml')
    policy=load_evidence_config(ROOT/'configs/stage-evidence-v1.yaml')
    postings=project_witnesses(ss.values(),aa,entities,run.normalized.source_settings,config,policy)
    profiles={aid:profile(a,entities,run.normalized.source_settings[a.source_namespace],config) for aid,a in aa.items()}
    native_rows=[json.loads(line) for line in args.input.read_text(encoding='utf-8-sig').splitlines() if line.strip()]
    raw_digest={content_digest(a.raw_alert):aid for aid,a in aa.items()}
    native={row['event_id']:raw_digest[content_digest(row['event'])] for row in native_rows}
    wrappers={native[row['event_id']]:row for row in native_rows}
    reverse={v:k for k,v in native.items()}
    owner={aid:s.stage_id for s in ss.values() for aid in s.alert_ids}
    gt=json.loads((args.dataset_root/'ground_truth/edges.json').read_text(encoding='utf8'))
    gt_stages=json.loads((args.dataset_root/'ground_truth/stages.json').read_text(encoding='utf8'))
    labels={native[native_id]:s['stage_id'] for s in gt_stages for native_id in s['member_alert_ids']}
    decisions={(d.stage_a_id,d.stage_b_id):d for d in run.evidence_result.decisions}
    candidates={(c.stage_a_id,c.stage_b_id):c for c in run.candidates}
    evidence_by_pair=defaultdict(list)
    for e in run.evidence_result.evidence:
        evidence_by_pair[(e.stage_a_id,e.stage_b_id)].append(e)
    host_aliases=defaultdict(set)
    for a in aa.values():
        if a.host:
            for field in ('asset_id','host_id','server_host_id'):
                if a.raw_alert.get(field):
                    host_aliases[a.host].add(a.raw_alert[field])

    def alert_trace(aid):
        a=aa[aid]
        s=ss[owner[aid]]
        actual_postings=[asdict(o) for bucket in postings[s.stage_id].values() for o in bucket if o.alert_id==aid]
        return dict(native_event_id=reverse[aid],stage_id=s.stage_id,community_id=s.community_id,
            raw_wrapper=wrappers[aid],canonical_alert=a.model_dump(mode='json'),
            entity_extraction=[dict(occurrence=o.model_dump(mode='json'),entity=entities[o.entity_id].model_dump(mode='json'),
                raw_value=EvidencePointer(alert_id=aid,pointer=o.raw_pointer,side='shared').resolve(aa)) for o in a.entity_occurrences],
            contexts=[c.model_dump(mode='json') for c in a.contexts],bindings=[asdict(b) for b in profiles[aid].bindings],
            stage_candidate_features=[f.model_dump(mode='json') for f in run.candidate_result.features
                if f.stage_id==s.stage_id and any(w.alert_id==aid for w in f.witnesses)],stage8_actual_postings=actual_postings)

    traces=[]
    for edge in gt:
        alert_pairs=sorted({(native[w['source_alert_id']],native[w['target_alert_id']]) for w in edge['binding_evidence']})
        pairs=sorted({tuple(sorted((owner[a],owner[b]))) for a,b in alert_pairs if owner[a]!=owner[b]})
        details=[]
        for pair in pairs:
            d=decisions.get(pair)
            witnesses=evidence_by_pair[pair]
            directional=[e for e in witnesses if e.evidence_strength_class=='DIRECTIONAL_STRONG']
            details.append(dict(stage_a_id=pair[0],stage_b_id=pair[1],candidate=candidates[pair].model_dump(mode='json') if pair in candidates else None,
                decision=d.model_dump(mode='json') if d else None,
                directional_evidence_status='NO_DIRECTIONAL_EVIDENCE' if not directional else 'DIRECTIONAL_EVIDENCE_PRESENT',
                directional_witnesses=[e.model_dump(mode='json') for e in directional],
                valid_witness_counts=dict(Counter(e.evidence_strength_class for e in witnesses if e.valid)),
                evidence_type_counts=dict(Counter(e.evidence_type for e in witnesses)),
                invalid_witnesses=[e.model_dump(mode='json') for e in witnesses if not e.valid],
                all_evidence_ids=[e.evidence_id for e in witnesses]))
        facts=[]
        for src,dst in alert_pairs:
            a,b=aa[src],aa[dst]
            same_tokens=[dict(kind=l.kind,value=l.value,source_pointer=l.raw_pointer,target_pointer=r.raw_pointer,
                source_scope=l.scope,target_scope=r.scope,same_scope=l.scope==r.scope)
                for l in a.contexts for r in b.contexts if l.kind==r.kind and l.value==r.value]
            protocol=lambda aid: [value for kind,value,_ in profiles[aid].weak_contexts if kind=='protocol']
            tuple_values=lambda x: dict(src_ip=x.src_ip,src_port=x.src_port,dst_ip=x.dst_ip,dst_port=x.dst_port)
            facts.append(dict(source_alert_id=src,target_alert_id=dst,raw_fields_preserved=a.raw_alert==wrappers[src]['event'] and b.raw_alert==wrappers[dst]['event'],
                source_process_raw={k:a.raw_alert.get(k) for k in ('process_id','process_start_time','process_guid','process_instance_id','executable','process_name')},
                target_parent_raw={k:b.raw_alert.get(k) for k in ('parent_process_id','parent_process_start_time','parent_process_guid','parent_process_instance_id','parent_executable','parent_process_name')},
                network_tuples=[dict(**tuple_values(x),protocol=protocol(x.alert_id)) for x in (a,b)],
                exact_ordered_four_tuple=tuple_values(a)==tuple_values(b),reversed_four_tuple=(a.src_ip,a.src_port,a.dst_ip,a.dst_port)==(b.dst_ip,b.dst_port,b.src_ip,b.src_port),
                source_native_flow_present=a.raw_alert.get('flow_id') is not None,target_native_flow_present=b.raw_alert.get('flow_id') is not None,
                source_settings=asdict(run.normalized.source_settings[a.source_namespace]),target_settings=asdict(run.normalized.source_settings[b.source_namespace]),
                equal_context_tokens=same_tokens,observed_hostname_asset_aliases={x.host:sorted(host_aliases[x.host]) for x in (a,b) if x.host},
                host_entities=[[entities[o.entity_id].model_dump(mode='json') for o in x.entity_occurrences if o.role.value=='host'] for x in (a,b)],
                scope_is_proven_independent_environment=False,authoritative_cross_source_connection_namespace_present=False))
            parent=b.parent_process
            hosts=[{o.entity_id for o in x.entity_occurrences if o.role.value=='host'} for x in (a,b)]
            # Diagnostic inference only: a reliable native ProcessStart record
            # may attest that its parent lived from parent birth to child birth.
            # This is stronger than a PID/narrow-window guess, but requires a
            # source contract certifying these roles before a future binding.
            interval=None
            if a.process and parent and b.process and parent.start_time and b.process.start_time:
                same_host=bool(hosts[0]&hosts[1])
                fits=parent.start_time<=a.timestamp<=b.process.start_time
                same_pid=a.process.pid is not None and a.process.pid==parent.pid
                conflicting_births=sorted({x.process.start_time for x in aa.values() if x.process and x.process.pid==parent.pid
                    and x.process.start_time and x.process.start_time!=parent.start_time
                    and parent.start_time<=x.timestamp<=b.process.start_time
                    and hosts[0]&{o.entity_id for o in x.entity_occurrences if o.role.value=='host'}})
                interval=dict(parent_birth=parent.start_time,child_birth=b.process.start_time,source_event_time=a.timestamp,
                    same_formal_host=same_host,same_pid=same_pid,source_inside_attested_interval=fits,
                    conflicting_observed_process_births=conflicting_births,
                    explicit_native_child_creation=b.raw_alert.get('operation')=='ProcessStart',
                    candidate_for_future_upstream_binding=bool(same_host and same_pid and fits and not conflicting_births and b.raw_alert.get('operation')=='ProcessStart'),
                    status='CONDITIONAL_AUDIT_INFERENCE_NOT_PRODUCTION_EVIDENCE',
                    additional_contract_required='trusted parent-at-child-birth semantics, common host/boot authority, reliable process birth clocks, unique continuous lifetime and no contradictory PID reuse',
                    raw_fields_must_not_be_backfilled=True)
            facts[-1]['process_lifetime_interval_projection_candidate']=interval
        traces.append(dict(edge_id=edge['edge_id'],gt_source_stage=edge['source_stage'],gt_target_stage=edge['target_stage'],
            gt_binding_evidence=edge['binding_evidence'],candidate_recalled=all(pair in candidates for pair in pairs),
            stage_pairs=details,binding_fact_checks=facts,alerts=[alert_trace(aid) for aid in sorted({i for p in alert_pairs for i in p})]))

    # Audit BOTH evaluation interpretations. The old acceptance metric checks
    # only GT binding-witness Stage pairs, not every possible GT-member pair.
    stage_progressions={(g['source_stage'],g['target_stage']):g['edge_id'] for g in gt}
    directed_mapping=[]
    for d in run.evidence_result.decisions:
        if d.relation_type!='DIRECTED_EDGE':
            continue
        directional=[e for e in evidence_by_pair[(d.stage_a_id,d.stage_b_id)] if e.valid and e.evidence_strength_class=='DIRECTIONAL_STRONG']
        combos=Counter()
        for e in directional:
            src,dst=(e.alert_a_id,e.alert_b_id) if e.direction_claim=='A_TO_B' else (e.alert_b_id,e.alert_a_id)
            combos[(labels[src],labels[dst])]+=1
        primary=next(e for e in directional if e.evidence_id==d.primary_evidence_id)
        psrc,pdst=(primary.alert_a_id,primary.alert_b_id) if primary.direction_claim=='A_TO_B' else (primary.alert_b_id,primary.alert_a_id)
        direct_gt=sorted({stage_progressions[pair] for pair in combos if pair in stage_progressions})
        directed_mapping.append(dict(candidate_id=d.candidate_id,from_stage_id=d.from_stage_id,to_stage_id=d.to_stage_id,
            evidence_type=primary.evidence_type,primary_witness_native_ids=[reverse[psrc],reverse[pdst]],
            primary_witness_gt_stages=[labels[psrc],labels[pdst]],primary_witness_matches_gt_progression=stage_progressions.get((labels[psrc],labels[pdst])),
            all_directional_witness_gt_combinations=[dict(from_gt_stage=left,to_gt_stage=right,witness_count=count,
                matching_gt_edge=stage_progressions.get((left,right))) for (left,right),count in sorted(combos.items())],
            any_witness_matches_gt_progression=direct_gt))
    return traces,directed_mapping,host_aliases


def finalize(args,run,aa,ss,entities,before,identical,graph,associative,context):
    traces,directed_mapping,host_aliases=gt_audit(args,run,aa,ss,entities)
    save(args.output,'gt_full_traces.json',traces)
    save(args.output,'directed_gt_mapping.json',directed_mapping)
    findings={
      'GT-E02':dict(root_cause='UPSTREAM_IDENTITY_PROJECTION_MISSING',classification='IMPLEMENTATION_GAP',
        explanation='同一 WAF namespace 中，两端 server_host=t5-prod-frontend-00、server_ip=10.0.1.5、application_session_id 和 upload-ticket 都有原始观测；后端记录同时携带 server_host_id。②按有无 asset_id 生成不同 HOST，ContextRef 的 host_scope 随之分裂，object binding 也按两个 HOST 分裂。当前 hostname→asset_id 共现映射在125条中无歧义，但没有有证据、有效期和部署作用域的 alias 投影。⑧根本未抽出 OBJECT_HANDOFF，不是已有 Witness 被 veto。',
        recommended_layer='② Host Alias / Object-Session Identity Projection',secondary=['需要将观测 alias 的来源、部署作用域与有效期建模；不能仅以 IP 或 GT 断言同主机。']),
      'GT-E05':dict(root_cause='DATA_INSUFFICIENT',classification='DATA_EVIDENCE_INSUFFICIENT',
        explanation='EDR 和 Auth 原始四元组方向一致，connection_id 同值；Auth raw 没有 protocol、flow_id 或声明该 token 为跨源权威连接标识的字段，Adapter 未丢失这些字段。两端 ContextRef 处于不同 source/host scope，不能从端口22或service=sshd补出TCP，也不能把相同token当成已认证桥接。',
        recommended_layer='② Cross-Source Connection Projection + 采集侧连接身份契约',secondary=['当前缺少统一投影能力，但仅新增投影函数或放宽 scope 并不能补足权威桥接证据。']),
      'GT-E06':dict(root_cause='UPSTREAM_IDENTITY_PROJECTION_MISSING',classification='IMPLEMENTATION_GAP',
        explanation='Auth 与 EDR 正式 HOST 已相同，raw logon_id 同值且字段明确属于认证上下文；实际 ContextRef 却仍分别落在 authentication/edr namespace。尚未建立以可信 HOST、logon_id、认证域/会话生命周期及源语义契约约束的统一 AuthSession。Auth raw 确实只有PID801，没有start_time/GUID或executable。另有条件性区间线索：Auth事件位于EDR所述parent birth与child birth之间；只有源契约证明父进程在子进程出生时仍存活、共同host/boot与时钟可信且无PID复用冲突时，未来②才可做连续生命周期绑定；不能仅复制parent_start_time或按窄时间窗补身份。',
        recommended_layer='② Host-scoped AuthSession / 有权威生命周期约束的Process Identity Projection',secondary=['严格进程身份该端未直接观测；区间桥接是待验证契约下的推断，不是本轮生产证据。','PID_ONLY_LINK_SAFE=false；时间窄、名称相同也不能排除PID复用。']),
      'GT-E07':dict(root_cause='DATA_INSUFFICIENT',classification='OBSERVABILITY_GAP',
        explanation='EDR/Firewall 原始五元组方向完全相同，connection_id 同值，Firewall 有native flow ID，EDR raw 中没有；没有Adapter丢字段。两端无已声明共同network/session authority，shared vendor字符串不等于连接ID全局唯一契约。Firewall 的start/end也不能单独证明EDR的该token属于同一个生命周期。真实攻击过程在GT中已知，但现有可信跨设备连接桥接尚不可观测。',
        recommended_layer='② CrossSourceNetworkSession能力 + 采集侧权威 connection/flow bridge',secondary=['native flow ID 本身 source-local；不能把单端ID复制到EDR，也不能仅据五元组/token放宽scope。'])
    }
    for trace in traces:
        if trace['edge_id'] in findings:
            trace['root_cause_assessment']=findings[trace['edge_id']]
    save(args.output,'gt_full_traces.json',traces)
    refs=[code_ref('backend/app/stage_evidence/extraction.py','for left in li[key]'),
        code_ref('backend/app/stage_evidence/extraction.py',"if left.role == right.role == 'process'"),
        code_ref('backend/app/stage_evidence/extraction.py',"elif kind == 'flow':"),
        code_ref('backend/app/stage_evidence/extraction.py',"add(assoc,left,right"),
        code_ref('backend/app/stage_evidence/validation.py','elif associative:'),
        code_ref('backend/app/entities/front_data.py',"host_id, host_pointer = observed"),
        code_ref('backend/app/entities/front_data.py',"host_kind = 'asset_id'"),
        code_ref('backend/app/entities/context.py','base = settings.session_scope'),
        code_ref('backend/app/entities/extraction.py',"if contract == 'front-data-v1'"),
        code_ref('backend/app/adapters/base.py','self.normalization.host_aliases'),
        code_ref('backend/app/adapters/multisource.py','def additional_entities'),
        code_ref('backend/app/stages/evidence.py',"if left_behavior != right_behavior"),
        code_ref('scripts/verify_stage8_evidence.py',"witness_pairs = sorted"),
        code_ref('configs/front-data-profiles.yaml','sources:')]
    # Attach Stage ⑥'s actual split diagnostics to the largest context clique.
    cliques=[r for r in associative['identity_postings'] if r['associative_identity_clique']]
    pure_cliques=[r for r in cliques if r['entirely_undirected_clique']]
    largest=(pure_cliques or cliques)[0] if cliques else None
    if largest:
        aids=set(largest['alert_ids'])
        largest['stage6_split_diagnostic_counts']=dict(Counter(d['reason'] for d in run.stages.diagnostics
            if len(d.get('alert_ids',[]))==2 and set(d['alert_ids'])<=aids and d.get('decision')=='keep_separate'))
        largest['stage_descriptions']=[dict(stage_id=sid,behavior=ss[sid].behavior,alert_count=ss[sid].alert_count,
            start=ss[sid].start_time,end=ss[sid].end_time,community_id=ss[sid].community_id) for sid in largest['stage_ids']]
    ee={e.evidence_id:e for e in run.evidence_result.evidence}
    ds={(d.stage_a_id,d.stage_b_id):d for d in run.evidence_result.decisions}
    redundant=set(map(tuple,associative['redundant_pairs']))
    undirected=[d for d in run.evidence_result.decisions if d.relation_type=='UNDIRECTED_EDGE']

    def describe(pair):
        d=ds[pair]
        primary=ee[d.primary_evidence_id]
        return dict(decision=d.model_dump(mode='json'),primary_witness=primary.model_dump(mode='json'),
            communities=[ss[sid].community_id for sid in pair],
            raw_fields=[dict(alert_id=p.alert_id,pointer=p.pointer,value=p.resolve(aa)) for p in primary.raw_pointers])

    nonredundant=[d for d in undirected if (d.stage_a_id,d.stage_b_id) not in redundant]
    reasonable=next((d for d in nonredundant if ee[d.primary_evidence_id].evidence_type=='SAME_PROCESS_INSTANCE'),nonredundant[0] if nonredundant else undirected[0])
    suspicious=next((d for d in undirected if (d.stage_a_id,d.stage_b_id) in redundant),None)
    samples=dict(A_largest_undirected_clique=largest,B_most_witnesses=associative['pair_witness_counts'][0],
        B_largest_cartesian_claim=associative['repeated_claims'][0] if associative['repeated_claims'] else None,
        C_reasonable_undirected=describe((reasonable.stage_a_id,reasonable.stage_b_id)),
        D_potentially_redundant_undirected=describe((suspicious.stage_a_id,suspicious.stage_b_id)) if suspicious else None,
        E_to_H_gt_traces=[t for t in traces if t['edge_id'] in findings])
    save(args.output,'samples.json',samples)
    after=inventory(args.dataset_root)
    changed=sorted(p for p in before.keys()|after.keys() if before.get(p)!=after.get(p))
    dataset_changed=[p for p in changed if Path(p).is_relative_to(args.dataset_root.resolve())]
    production_changed=[p for p in changed if p not in dataset_changed]
    release=json.loads((args.dataset_root/'manifests/release_manifest.json').read_text(encoding='utf8'))
    release_mismatches=[p for p,h in release['file_sha256'].items() if sha(args.dataset_root/p)!=h]
    prod_tests=xml_counts(args.tests)
    audit_tests=xml_counts(args.audit_tests)
    blocking=[]
    if changed or release_mismatches:
        blocking.append('PROTECTED_FILES_CHANGED')
    if not prod_tests['passed'] or prod_tests['failed'] or prod_tests['errors']:
        blocking.append('PRODUCTION_TESTS_MISSING_OR_FAILED')
    if not audit_tests['passed'] or audit_tests['failed'] or audit_tests['errors']:
        blocking.append('AUDIT_TESTS_MISSING_OR_FAILED')
    primary_counts={kind:detail['RELATION_COUNT'] for kind,detail in associative['primary_attribution'].items()}
    primary_counts['OTHER']=sum(count for kind,count in primary_counts.items() if kind not in {
        'SAME_PROCESS_INSTANCE','SAME_SCOPED_FLOW','SAME_SCOPED_OBJECT','SAME_SCOPED_REQUEST','SAME_STRONG_SESSION'})
    directed_counts=Counter(ee[d.primary_evidence_id].evidence_type for d in run.evidence_result.decisions if d.relation_type=='DIRECTED_EDGE')
    witness_counts=[r['raw_witness_count'] for r in associative['pair_witness_counts']]
    broad_gt=sorted({edge for row in directed_mapping for edge in row['any_witness_matches_gt_progression']})
    supportive=sum(e.evidence_strength_class=='SUPPORTING_ONLY' for e in run.evidence_result.evidence)
    source_primary=Counter()
    for counts in context['source_pairs_primary'].values():
        source_primary.update(counts)
    flow_pairs={(e.stage_a_id,e.stage_b_id) for e in run.evidence_result.evidence if e.valid and e.evidence_type=='SAME_SCOPED_FLOW'
        and ds[(e.stage_a_id,e.stage_b_id)].relation_type=='UNDIRECTED_EDGE'}
    summary=dict(TASK_RESULT='SUCCESS' if not blocking else 'PARTIAL',STAGE_8_RELATION_QUALITY_AUDIT='PASS' if not blocking else 'PARTIAL',
        PRODUCTION_LOGIC_MODIFIED=bool(production_changed),DATASET_MODIFIED=bool(dataset_changed),
        GROUND_TRUTH_MODIFIED=any('ground_truth' in Path(p).parts for p in dataset_changed),
        **{k:run.evidence_result.statistics[k] for k in ('INPUT_ALERTS','INPUT_STAGE_COUNT','INPUT_CANDIDATE_PAIR_COUNT','DIRECTED_EDGE_COUNT','UNDIRECTED_EDGE_COUNT','NO_RELATION_COUNT')},
        **{k:v for k,v in graph.items() if k not in {'degree_by_stage','diagnostic_components'}},
        **context['community_counts'],UNDIRECTED_BY_PRIMARY_EVIDENCE_TYPE=primary_counts,
        ASSOCIATIVE_IDENTITY_CLIQUE=bool(cliques),CLIQUE_IDENTITY_COUNT=len(cliques),
        LARGEST_CLIQUE_STAGE_COUNT=largest['stage_count'] if largest else 0,
        LARGEST_CLIQUE_RELATION_COUNT=largest['relation_pair_count'] if largest else 0,
        CONTEXT_MEMBERSHIP_TREATED_AS_PAIRWISE_RELATION=True,
        POTENTIALLY_REDUNDANT_UNDIRECTED_EDGE_COUNT=len(redundant),NON_REDUNDANT_UNDIRECTED_EDGE_COUNT=len(undirected)-len(redundant),
        REDUNDANCY_RATIO=len(redundant)/(len(undirected) or 1),RAW_WITNESS_COUNT=len(run.evidence_result.evidence),
        UNIQUE_EVIDENCE_CLAIM_COUNT=associative['unique_claim_count'],LOGICALLY_DUPLICATE_WITNESS_COUNT=associative['logically_duplicate_count'],
        WITNESS_CARTESIAN_EXPLOSION=any(r['complete_cartesian_product'] and r['left_alert_count']>1 and r['right_alert_count']>1 for r in associative['repeated_claims']),
        AVG_WITNESS_PER_CANDIDATE=sum(witness_counts)/(len(witness_counts) or 1),MEDIAN_WITNESS_PER_CANDIDATE=statistics.median(witness_counts),
        P90_WITNESS_PER_CANDIDATE=round(quantile(witness_counts,.9),6),MAX_WITNESS_PER_CANDIDATE=max(witness_counts),
        DIRECTED_EDGE_BY_EVIDENCE_TYPE={**{kind:directed_counts[kind] for kind in ('PARENT_CHILD_PROCESS','REQUEST_RESPONSE','OBJECT_CREATE_EXECUTE','AUTH_ESTABLISH_USE','EXPLICIT_ATTESTED_RELATION','OBJECT_HANDOFF')},
            'OTHER':sum(n for k,n in directed_counts.items() if k not in {'PARENT_CHILD_PROCESS','REQUEST_RESPONSE','OBJECT_CREATE_EXECUTE','AUTH_ESTABLISH_USE','EXPLICIT_ATTESTED_RELATION','OBJECT_HANDOFF'})},
        DIRECTIONAL_EVIDENCE_DIVERSITY_LOW=len(directed_counts)==1,
        **{key.replace('-','_')+'_ROOT_CAUSE':v['root_cause'] for key,v in findings.items()},PID_ONLY_LINK_SAFE=False,
        HOST_ALIAS_PROJECTION='PARTIAL',PROCESS_IDENTITY_PROJECTION='PARTIAL',NETWORK_FLOW_PROJECTION='MISSING',
        SESSION_PROJECTION='PARTIAL',REQUEST_PROJECTION='PARTIAL',OBJECT_PROJECTION='PARTIAL',
        RELATION_DENSITY_ASSESSMENT='OVERCONNECTED_BY_ASSOCIATIVE_CLIQUES' if cliques and redundant else 'ACCEPTABLE_BUT_DENSE',
        GT_MISSING_EDGE_PRIMARY_CAUSE='MIXED',
        RECOMMENDED_FIX_LAYER=['⑧ Relation Semantics','② Identity Projection / 采集侧可信桥接','审计与评估口径','Evidence Summary'],
        RECOMMENDED_NEXT_ACTION='先明确共享上下文关联与直接攻击关系契约；验证可追溯的②别名/认证会话投影，补连接身份权威契约，再复审；本轮不修复、不进入⑨。',
        PRODUCTION_TEST_RESULT=prod_tests,AUDIT_SCRIPT_RESULT=dict(status='PASS' if not blocking else 'PARTIAL',tests=audit_tests),
        BLOCKING_ISSUES=blocking+(['若⑨目标是直接攻击关系图，需先解决共享上下文被展开为成对关系的语义问题。'] if cliques and redundant else []),
        AUDIT_EXECUTION_ERRORS=blocking,NON_BLOCKING_ISSUES=[
            '无向关系包含共享上下文的成对投影，不能直接解释为直接攻击推进。',
            '同identity结构冗余按逐边移除计算，不能据此同时删除全部标记边。',
            'GT有向0是指定binding Pair口径；其他Witness对GT阶段推进存在方向吻合。',
            '相同五元组/token不能自行证明跨源权威连接身份。'],
        STAGE_9_STARTED=False,CURRENT_PIPELINE_STAGE='STAGE_8_RELATION_QUALITY_AUDITED',NEXT_STAGE_NOT_STARTED=True,
        GT_BINDING_PAIR_DIRECTED_RELATIONS=sum(any(p['decision'] and p['decision']['relation_type']=='DIRECTED_EDGE' for p in t['stage_pairs']) for t in traces),
        GT_MEMBER_WITNESS_PROGRESSIONS_WITH_DIRECTED_EVIDENCE=broad_gt,
        DIRECTED_RELATIONS_MATCHING_ANY_GT_PROGRESSION_BY_PRIMARY_WITNESS=sum(bool(row['primary_witness_matches_gt_progression']) for row in directed_mapping),
        DIRECTED_RELATIONS_MATCHING_ANY_GT_PROGRESSION_BY_ANY_WITNESS=sum(bool(row['any_witness_matches_gt_progression']) for row in directed_mapping),
        SUPPORTING_ONLY_WITNESS_COUNT=supportive,OFFICIAL_RESULT_IDENTICAL_TO_COMPLETED_STAGE8=identical,
        SOURCE_PAIR_RELATION_COUNTS=dict(source_primary),
        SOURCE_PAIR_DIRECTED_COUNTS=context['source_pairs_primary'].get('DIRECTED_EDGE',{}),
        SOURCE_PAIR_UNDIRECTED_COUNTS=context['source_pairs_primary'].get('UNDIRECTED_EDGE',{}),
        FLOW_SUPPORTED_UNDIRECTED_PAIR_COUNT=len(flow_pairs),
        ENTIRELY_UNDIRECTED_CLIQUE_IDENTITY_COUNT=len(pure_cliques),
        RAW_FIELD_COVERAGE_BY_SOURCE={namespace:dict(alert_count=len(items),
            native_flow_id_count=sum(x.raw_alert.get('flow_id') is not None for x in items),
            raw_protocol_count=sum(x.raw_alert.get('protocol') is not None or x.raw_alert.get('proto') is not None for x in items),
            raw_process_start_count=sum(x.raw_alert.get('process_start_time') is not None for x in items),
            observed_sensor_values=sorted({x.sensor for x in items if x.sensor is not None}))
            for namespace in sorted({a.source_namespace for a in aa.values()})
            for items in [[a for a in aa.values() if a.source_namespace==namespace]]},
        SERIALIZED_PRODUCTION_RESULT_BYTES=(args.output/'current_official_result.json').stat().st_size,
        SUPPORTING_ONLY_COMPACT_WITNESS_BYTES=sum(len(encode(e.model_dump(mode='json')).encode('utf8')) for e in run.evidence_result.evidence if e.evidence_strength_class=='SUPPORTING_ONLY'),
        OFFICIAL_PIPELINE_CALL_COUNTS=dict(CALLS),PRODUCTION_RUNTIME_READS=sorted(READS))
    checks=dict(protected_file_count=len(before),protected_changed_files=changed,release_manifest_mismatches=release_mismatches,
        current_official_result_identical=identical,official_call_counts=dict(CALLS),production_runtime_reads=sorted(READS),
        graph_statistics_are_audit_only=True,quantile_definition='linear interpolation at (n-1)*p',
        density_definition='unique Stage Pair Relations / C(all current Stage nodes,2); directed edges use an undirected skeleton only for these diagnostics',
        redundancy_definition='for each existing undirected pair independently: another undirected path using exactly the same valid associative identity after omitting only that pair',
        logical_claim_definition='Stage Pair + evidence type + exact scoped identity + semantic direction + endpoint roles; Alert pairs and raw pointers retained as supporting observations',
        source_pair_definition='primary witness: each relation counted once; any valid strong witness: each source combo counted once per relation, totals may exceed relation count',
        clique_definition='one valid associative identity on at least 3 Stage nodes with every unordered pair already present; no new relations generated',
        recommendation_scope='analysis only; no counterfactual production reruns, scope merges, edge deletions, additions or direction changes')
    save(args.output,'integrity_and_definitions.json',checks)
    save(args.output,'findings.json',dict(gt_root_causes=findings,code_references=refs,primary_attribution=associative['primary_attribution'],
        top20_associative_identities=associative['identity_postings'][:20],top10_pairs_by_witness_count=associative['pair_witness_counts'][:10],
        top_clique_cases=cliques[:10],largest_undirected_clique=largest))
    save(args.output,'summary.json',summary)
    write_report(args.output,summary,graph,associative,context,samples,traces,directed_mapping,refs,checks)
    print(json.dumps({k:v for k,v in summary.items() if k not in {'PRODUCTION_RUNTIME_READS','OFFICIAL_PIPELINE_CALL_COUNTS'}},ensure_ascii=False,indent=2))


def write_report(out,summary,graph,associative,context,samples,traces,directed_mapping,refs,checks):
    lines=['# ⑧ Stage Relation 专项质量审核','','本报告只读；未构建正式⑨。完整数据流见 gt_full_traces.json；审计快照为本次实时①～⑧执行结果。',
        '审核PASS表示要求的只读分析、复现和保护检查已完成，不表示⑧不存在质量问题。BLOCKING_ISSUES列的是直接进入攻击关系图前的语义前置问题；AUDIT_EXECUTION_ERRORS单列审核执行失败。','',
        '## 验收与统计口径','','```text']
    lines += [k+'='+encode(v) for k,v in summary.items() if k not in {'PRODUCTION_RUNTIME_READS','OFFICIAL_PIPELINE_CALL_COUNTS'}]
    lines += ['```','', '```json',json.dumps(checks,ensure_ascii=False,indent=2),'```','',
        '## 关系密度及来源','','全局密度仅描述42节点的简单关系骨架，不能掩盖特定identity诱导子集的完全图。',
        '共享上下文证据本身可以真实，但把上下文成员身份投影为所有Stage两两直接攻击关系会产生语义过度连接。未发现SUPPORTING_ONLY单独建边。','',
        '### 无向关系 primary attribution','','```json',json.dumps(associative['primary_attribution'],ensure_ascii=False,indent=2),'```','',
        'primary按稳定evidence ID选择，因此primary类型统计不是全部支持证据的独立因果归因；identity audit遍历所有合法ASSOCIATIVE_STRONG证据。','',
        '### Top 20 identity postings','','|类型|安全摘要|Stage|实际Pair|理论Pair|纯无向clique|Community数|Alert数|跨度秒|来源|',
        '|---|---|---:|---:|---:|---|---:|---:|---:|---|']
    for row in associative['identity_postings'][:20]:
        lines += ['|'+row['identity_type']+'|'+row['identity_hash'][:16]+'|'+str(row['stage_count'])+'|'+str(row['relation_pair_count'])+'|'+str(row['theoretical_pair_count'])+'|'+str(row['entirely_undirected_clique'])+'|'+str(len(row['communities_covered']))+'|'+str(row['alerts_covered'])+'|'+str(row['time_span']['seconds'])+'|'+', '.join(row['source_namespaces'])+'|']
    lines += ['','### Community / Source / Time','','```json',json.dumps(context,ensure_ascii=False,indent=2),'```','',
        '## Witness膨胀','','逻辑等价按Stage Pair、类型、完整scoped identity、方向和端点角色分组；raw Witness不删除。',
        'SUPPORTING_ONLY不会提升建边强度，仍会占用完整JSON及指针追溯空间。建议未来以逻辑claim为主记录、Alert Pair为完整可展开支持列表，保持全部原始指针。','',
        '### Top 10 Stage Pair','','```json',json.dumps(associative['pair_witness_counts'][:10],ensure_ascii=False,indent=2),'```','',
        '## 专项样本 A–D','']
    for key in ('A_largest_undirected_clique','B_most_witnesses','B_largest_cartesian_claim','C_reasonable_undirected','D_potentially_redundant_undirected'):
        lines += ['### '+key,'','```json',json.dumps(samples[key],ensure_ascii=False,indent=2),'```','']
    lines += ['C案例：完整强identity及双端原始Witness足以支持“共享上下文关联”，在当前⑧契约下应保留；它仍不是因果推进证明。',
        'D案例：移除该一条边后，仍经相同identity的其他Stage连通。它可能只是上下文clique的成对展开；结构冗余不是删除授权，也不意味着原始事实为假。',
        '最大clique的真实⑥拆分原因已列于A样本。不同request/URL/command、行为和时间约束会让同一上下文保留多个Stage；不能凭clique反推⑥一定错误。',
        '两个10-Stage flow clique分别来自IDS与WAF，时间跨度324秒和189秒；没有证据表明这是跨小时生命周期误合并。更直接的问题是同一正常上下文被展开为全Pair关联。',
        '95条primary为flow的无向边来自同源记录（IDS 50、WAF 45）；全部强flow支持去重后也覆盖95个无向Pair。不同identity支持的Pair会重叠，不能直接相加。相同source_namespace不等于已经证明同一物理设备，仍需sensor/device角色信息。','',
        '## GT E02/E05/E06/E07完整路径','']
    for trace in traces:
        if 'root_cause_assessment' not in trace:
            continue
        finding=trace['root_cause_assessment']
        lines += ['### '+trace['edge_id'],'',finding['explanation'],'',
            '根因：`'+finding['root_cause']+'`；分类：`'+finding['classification']+'`；建议层：'+finding['recommended_layer']+'。','',
            '实际顺序：GT阶段/Witness → 当前Stage → raw wrapper → Canonical → Entity → ContextRef/Binding → Candidate Features → ⑧Postings → Witness → Validation → NO_RELATION。',
            '完整字段和每一步对象保存在gt_full_traces.json；下列为当前路径中决定缺边的真实事实与生产决策。','',
            '```json',json.dumps(dict(gt_source_stage=trace['gt_source_stage'],gt_target_stage=trace['gt_target_stage'],
                facts=trace['binding_fact_checks'],stage_pairs=[{k:v for k,v in p.items() if k not in {'all_evidence_ids','directional_witnesses'}} for p in trace['stage_pairs']]),ensure_ascii=False,indent=2),'```','',
            '⑧状态：未构造出合法方向Witness；没有已存在方向Witness被Validation过严拒绝的证据。','']
    lines += ['## GT方向评估口径专项结论','','原验收器只取GT binding_evidence所指Alert对应的Stage Pair，所以这些Pair的有向数量是0。',
        '这不代表所有12条有向关系均不对应GT progression。下面逐条保留生产方向，仅在离线侧映射GT成员标签；不会从GT顺序或时间生成方向。','',
        '```json',json.dumps(directed_mapping,ensure_ascii=False,indent=2),'```','',
        '7条GT指定Pair的directional_witnesses、NO_DIRECTIONAL_EVIDENCE状态与拒绝原因见gt_full_traces.json。',
        'GT-S03/S04/S05标签与当前细分Stage并非一对一；有向边可以发生在同一GT阶段内部、跳过GT阶段，或使用GT未指定的另一组Witness。不能混用这些评估口径。','',
        '## Cross-Source Projection能力与建议','','|能力|当前判断|实际限制|','|---|---|---|',
        '|Host Alias|PARTIAL|有字符串host_aliases和asset_id优先；当前空配置，没有observed hostname↔asset_id绑定记录|',
        '|Process Instance|PARTIAL|已能基于同一HOST+PID+start/GUID跨源复用；不能从PID-only安全恢复缺失出生事实|',
        '|Network Flow|MISSING|当前正式路径没有可信CrossSourceNetworkSession投影；source-local native ID及namespace设置不等于连接生命周期桥接|',
        '|Session|PARTIAL|ContextRef及显式session_scope能力存在；正式配置按source分隔，没有host-local auth session跨源映射|',
        '|Request|PARTIAL|有typed scoped request；不同field/source不会自动声明同一request authority|',
        '|Object|PARTIAL|有HOST-scoped object和handoff角色；继承HOST alias不统一的问题|','',
        'legacy additional_entities/session_scope仍有typed session投影代码，但正式入口显式使用front-data-v1，不调用legacy extractor；不能把兼容路径能力当作当前生产已实现。',
        '优先澄清⑧关系契约：上下文关联可保留为context-membership/association；直接攻击关系要求额外pair-specific语义。⑨只能根据已明确的语义做可追溯投影或展示压缩，不能暗删真关系来掩盖⑧契约歧义。',
        '②优先处理可由原始共现证明的Host alias及host-local AuthSession；网络桥接先补共同authority、sensor/zone、生命周期或原生cross-reference契约。缺此证据时继续NO_RELATION，不按GT放宽scope。',
        'E06另有条件性进程区间线索：Auth事件17:54:33.907404Z位于EDR parent birth 17:53:03.907404Z与child birth 17:55:35.907404Z之间。若源契约保证该父进程在子进程出生时仍存活，这可为②的连续生命周期绑定提供证明；必须排除host/boot、时钟和PID复用歧义。它不是PID-only或固定短窗口fallback，本轮未把该推断加入生产证据。',
        'E05/E07当前缺少权威跨源桥接的前提，不是要求新增一个按相同token放行的⑧ Evidence Type。现有SAME_TRUSTED_CONNECTION可以消费将来经②确证的identity；即便建立共同连接，连接共享本身仍不提供GT方向。',
        '原始字段覆盖检查显示：12条Auth都无protocol/flow_id/process_start_time；34条EDR都无flow_id。这说明当前payload缺字段且Adapter没有丢失它们，不能由此断言产品设备永远不具备输出这些字段的能力。',
        '当前不建议将139条无向上下文关联直接作为直接攻击关系输入⑨；如将来只做明确标注的上下文关联展示，需先固定类型契约及评估口径。本轮停在⑧。','',
        '## 代码定位','']
    for ref in refs:
        lines += ['- ['+Path(ref['path']).name+':'+str(ref['line'])+']('+ref['path'].replace('\\','/')+':'+str(ref['line'])+')：`'+ref['text']+'`']
    lines += ['','## 保护结果','','生产、配置、数据和GT哈希差异见integrity_and_definitions.json；未修改生产算法，未增加/删除/定向任何关系。']
    (out/'REPORT.md').write_text('\n'.join(lines)+'\n',encoding='utf8')


if __name__=='__main__':
    sys.stdout.reconfigure(encoding='utf8')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',type=Path,default=DATA/'final/attack125_final.jsonl')
    parser.add_argument('--dataset-root',type=Path,default=DATA)
    parser.add_argument('--output',type=Path,default=ROOT/'outputs/stage8_relation_quality_audit')
    parser.add_argument('--tests',type=Path,nargs='*',default=[])
    parser.add_argument('--audit-tests',type=Path,nargs='*',default=[])
    parser.add_argument('--capture-only',action='store_true')
    args=parser.parse_args()
    protect(args) if args.capture_only else verify(args)
