"""Bounded post-hoc progression search. Never creates a domain edge or feature."""
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime, timedelta
import json

import v5_evidence_adjudication as m
import v5_evidence_adjudication_evidence as e


@contextmanager
def scorer_for(alerts, settings, config):
    """Replay frozen scoring with temporary storage confined to this task."""
    with m.d.bounded_execution(m.OUT/'spill'):
        groups=m.d.deduplicate(alerts,config,settings).groups
        extracted=m.d.extract_entities(alerts,settings)
        index=m.d.AlertIndex(extracted.alerts,groups,extracted.entities)
        yield m.d.CorrelationScorer(index,config,settings)


def local_expansion(blind):
    """Stream the compressed export once; inspect only the bounded endpoint window."""
    seed = next((r for r in blind if r['pair_id'] in {
        a['pair_id'] for a in m.d.read(m.OUT/'semantic_decisions.json')['decisions']
        if a['label'] in ('CONFIRMED_RELATED','PLAUSIBLE_RELATED')}),None)
    if seed is None:
        return dict(records=[],windows=[],reason='No positive target seed; semantic search still runs.')
    endpoints=[seed['alert_a'],seed['alert_b']]
    times=[datetime.fromisoformat(x['timestamp'].replace('Z','+00:00')) for x in endpoints]
    lo,hi=min(times)-timedelta(minutes=60),max(times)+timedelta(minutes=60)
    rows=[]; scanned=0
    for rec in m.d.read_cptc_file(m.d.RAW):
        scanned+=1
        raw=rec.eve
        if raw.get('src_ip')!=endpoints[0]['src_ip'] or raw.get('dest_ip')!=endpoints[0]['dst_ip']:
            continue
        stamp=datetime.strptime(raw['timestamp'],'%Y-%m-%dT%H:%M:%S.%f%z')
        if lo<=stamp<=hi:
            if len(rows)>=10000:
                raise ValueError('bounded_local_expansion_alert_limit')
            rows.append(dict(ordinal=rec.ordinal,raw_alert=raw))
    windows=[]
    for minutes in (5,15,30,60):
        local=[r for r in rows if min(times)-timedelta(minutes=minutes)<=
            datetime.strptime(r['raw_alert']['timestamp'],'%Y-%m-%dT%H:%M:%S.%f%z')<=max(times)+timedelta(minutes=minutes)]
        windows.append(dict(window_minutes=minutes,alerts_inspected=len(local),candidate_pairs_produced=0,
            semantic_hits=sum(bool(e.attack_action(r['raw_alert'].get('http',{}).get('url'),
                e.decoded_payload(r['raw_alert']) or '')) for r in local),
            explanation='No third alert on the directed seed endpoint context; no new nominations.'))
    result=dict(anchor_pair_id=seed['pair_id'],window_minutes=60,scanned_records=scanned,
        selected_alerts=len(rows),policy='single-pass bounded endpoint window retrieval; hard limit 10000; no full-dataset pair enumeration',
        records=rows,windows=windows,source_path=m.d.RAW.relative_to(m.ROOT).as_posix(),source_sha256=m.d.file_digest(m.d.RAW))
    m.save('local_expansion_raw.json',result)
    return result


def scan_hypotheses(entries):
    """Inspect explicit request actions in scoped flows, one pass, no triplets."""
    flows=defaultdict(list)
    for dataset,a,locator in entries:
        if dataset!='cptc_t5_dev_10k':
            continue
        raw=a.raw_alert
        action=e.attack_action(a.url,e.decoded_payload(raw) or '')
        if action and raw.get('flow_id') is not None and raw.get('tx_id') is not None:
            key=(a.source_namespace,raw['flow_id'],a.src_ip,a.src_port,a.dst_ip,a.dst_port)
            flows[key].append((a,locator,action))
    eligible=[]
    for key,rows in sorted(flows.items(),key=lambda item:str(item[0])):
        by_tx={}
        for a,locator,action in sorted(rows,key=lambda x:(x[0].timestamp,x[0].alert_id)):
            by_tx.setdefault(a.raw_alert['tx_id'],(a,locator,action))
        chosen=[]; seen=set()
        for tx,(a,locator,action) in sorted(by_tx.items()):
            if action in seen or (chosen and a.timestamp<=chosen[-1][0].timestamp):
                continue
            seen.add(action);chosen.append((a,locator,action))
        if len(chosen)>=3:
            eligible.append((key,chosen))
    # Stable pre-score budget, independent of any score or nomination result.
    selected=eligible[:8]
    return selected,dict(scoped_flows_inspected=len(flows),eligible_multiaction_flows=len(eligible),
        selected_flow_budget=8,selected_flows=len(selected),selection='lexical scoped flow key; distinct actions and transactions; before score',
        brute_force_triplets=False)


def search(entries,blind):
    expansion=local_expansion(blind)
    hypotheses,stats=scan_hypotheses(entries)
    # No replay of candidate selection; exact archived frozen nominations.
    archived={}
    for line in (m.DESIGN/'candidate_pairs.jsonl').open(encoding='utf8'):
        row=json.loads(line)
        archived[(row['source_alert_id'],row['target_alert_id'])]=row
    packages=[]
    config,_,_=m.d.load_frozen_config()
    meta=m.d.read(m.OUT/'input_manifest.json')['cptc_t5_dev_10k']
    settings={k:m.d.AdapterSettings(**v) for k,v in meta['source_settings'].items()}
    alerts=[a for dataset,a,_ in entries if dataset=='cptc_t5_dev_10k']
    with scorer_for(alerts,settings,config) as scorer:
        for key,chosen in hypotheses:
            edges=[]
            for (a,_,action_a),(b,_,action_b) in zip(chosen,chosen[1:]):
                rep_pair=tuple(sorted((scorer.index.owner[a.alert_id],scorer.index.owner[b.alert_id])))
                nomination=archived.get(rep_pair)
                pair=scorer.score_pair(*sorted((a.alert_id,b.alert_id)))
                view=m.d.state_projection(pair,scorer)
                m.d.validate_refs(view,scorer)
                prototypes=m.ev.compare(view,m.d.design())
                primary=prototypes['b']
                non_threshold_reasons=[reason for reason in primary['admission_reasons']
                    if reason!='below_reference_threshold']
                edge=dict(**{'from':a.alert_id,'to':b.alert_id},
                    semantic_label='CONFIRMED_RELATED',semantic_scope='same active vulnerability-scanning operation',
                    direction_grounded=True,direction_scope='request transaction order; no causal exploitation claim',
                    score=primary['score'],admitted=bool(nomination and primary['admitted']),
                    prototypes=prototypes,v4_score=pair.score,v4_valid=pair.valid,
                    v4_breakdown=scorer.breakdown(pair).model_dump(mode='json'),
                    RAW_VISIBLE=True,CANONICAL_VISIBLE=True,CANDIDATE_NOMINATED=nomination is not None,
                    SCORED=nomination is not None,ADMITTED=bool(nomination and primary['admitted']),
                    gate_passed=not non_threshold_reasons,
                    non_threshold_admission_reasons=non_threshold_reasons,
                    counterfactual_score_if_not_nominated=nomination is None,
                    nomination=nomination,representative_pair=list(rep_pair),
                    score_scope='diagnostic original member pair; no production edge is published',
                    actions=[action_a,action_b],support=dict(flow_id=key[1],
                        tx_ids=[a.raw_alert['tx_id'],b.raw_alert['tx_id']],
                        alert_ids=[a.alert_id,b.alert_id],raw_pointers=[dict(alert_id=alert.alert_id,
                            pointer=path,side='shared') for alert in (a,b)
                            for path in ('/flow_id','/tx_id','/http/url','/payload')
                            if path!='/payload' or alert.raw_alert.get('payload')]))
                edge['failure_stage']=e.failure_stage(edge)
                edges.append(edge)
            package=dict(progression_id='hyp_'+e.digest([a.alert_id for a,_,_ in chosen]),
                alerts=[a.alert_id for a,_,_ in chosen],edges=edges,
                attack_story='Ordered sensitive-file, SQL, script or command probes in one scanner connection. '
                    'Requests demonstrate attack attempts; no observed result enables the next action.',
                confidence='HIGH_FOR_COMMON_SCANNING_OPERATION',verified_progression=False,
                rejection_reason='Same-flow ordered probes alone do not verify attack-stage advancement or causal dependency. '
                    'A request to cmd.exe is not observed command execution; HTTP status is not exploit success.',
                evidence=dict(raw_alert_evidence=[dict(alert_id=a.alert_id,locator=locator,canonical=a.model_dump(mode='json'),
                    raw_alert=a.raw_alert,payload_decoded=e.decoded_payload(a.raw_alert),action=action)
                    for a,locator,action in chosen],
                    shared_entities=dict(source_namespace=key[0],flow_id=key[1],endpoint_tuple=list(key[2:])),
                    temporal_sequence=[a.timestamp for a,_,_ in chosen]),
                candidate_reachable=all(x['CANDIDATE_NOMINATED'] for x in edges),
                fully_admitted=all(x['ADMITTED'] for x in edges),level=None)
            e.validate_progression(package)  # adjacency is necessary, not sufficient for verification
            packages.append(package)
            m.save('progression_evidence/'+package['progression_id']+'.json',package)
    m.save('progression_hypotheses.json',packages)
    m.save('verified_progressions.json',dict(count=0,progressions=[],best_level=0,
        qualification='No verified >=2-edge attack-stage progression. Common scanning operations are separately retained as hypotheses.'))
    edge_list=[x for p in packages for x in p['edges']]
    manifest=dict(**stats,strategies=['A/B: expand sole plausible target pair at +/-5/15/30/60 min',
        'C: content-grounded distinct request actions within scoped flow; at most 8 flows'],
        alerts_inspected_by_slice=dict(Counter(dataset for dataset,_,_ in entries)),
        bounded_local_expansion={k:v for k,v in expansion.items() if k!='records'},
        archived_candidate_count=len(archived),archived_candidate_hash=m.d.file_digest(m.DESIGN/'candidate_pairs.jsonl'),
        hypotheses=len(packages),candidate_pairs_produced=len(edge_list),
        common_scanning_operation_edges=len(edge_list),verified_attack_progression_edges=0,
        candidate_reachable_hypothesis_edges=sum(x['CANDIDATE_NOMINATED'] for x in edge_list),
        score_ge_065_hypothesis_edges=sum(x['score']>=.65 for x in edge_list),
        admitted_hypothesis_edges=sum(x['ADMITTED'] for x in edge_list),
        failure_stages=dict(Counter(x['failure_stage'] for x in edge_list)),
        verified_progression_reachability=dict(candidate=None,score=None,admission=None,denominator=0,status='not_applicable'),
        best_level=0,verified_progressions=0,best_progression_length=0,consecutive_edges=0,
        primary_bottleneck='SOURCE_OBSERVABILITY',
        limitation='Cannot infer missed real progression or global candidate recall from unverified scanner hypotheses.',
        external_scenario_knowledge_used_for_scoring='NO',external_scenario_knowledge_used_for_nomination='NO',
        external_scenario_knowledge_used_for_post_hoc_adjudication='NO',production_domain_writes=0)
    m.save('progression_search_manifest.json',manifest)
    return manifest
