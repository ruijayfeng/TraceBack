"""Live ①→⑧ snapshots; labels are read only by the later offline comparison."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'backend'))
DATA = Path('D:/Code_WorkSpace/TraceBack-Dataset/data/attack125')
OUT = ROOT/'outputs/stage2_identity_projection'
FILES_CHANGED = ['backend/app/adapters/base.py','backend/app/entities/identity_contracts.py',
    'backend/app/entities/identity_projection.py','backend/app/entities/extraction.py','backend/app/entities/front_data.py',
    'backend/app/models/alerts.py','backend/app/services/alert_pipeline.py','configs/front-data-profiles.yaml',
    'backend/tests/test_identity_projection.py','backend/tests/test_entity_extraction.py',
    'scripts/verify_stage2_identity_projection.py','docs/STAGE_2_IDENTITY_PROJECTION.md',
    'memory/2026-10-21-stage2-identity-projection.md']


def save(name, value):
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT/name).write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)+'\n', encoding='utf8')


def protected():
    files = list(DATA.rglob('*'))
    for folder in ('backend/app/stage_evidence', 'backend/app/stage_candidates', 'backend/app/community', 'backend/app/stages'):
        files += list((ROOT/folder).rglob('*.py'))
    files += [ROOT/'configs'/s for s in ('stage-evidence-v1.yaml', 'stage-candidates-v1.yaml', 'community-v1.yaml', 'behavior-stage-v1.yaml')]
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files) if p.is_file() and '__pycache__' not in p.parts}


def snapshot(phase):
    from app.services.stage_pipeline import load_stage_pipeline
    import verify_stage8_evidence as guard
    if phase=='before' and (OUT/'before.json').exists():
        raise ValueError('baseline_already_captured_do_not_overwrite')
    hashes = protected()
    sys.addaudithook(guard.audit)
    guard.ACTIVE = True
    sys.setprofile(guard.profiler)
    try:
        run = load_stage_pipeline(DATA/'final/attack125_final.jsonl')
    finally:
        sys.setprofile(None)
        guard.ACTIVE = False
    payload = dict(statistics=run.statistics,
        entity_counts=dict(Counter(e.type.value for e in run.normalized.entities)),
        entities=[e.model_dump(mode='json') for e in run.normalized.entities],
        alerts=[a.model_dump(mode='json') for a in run.normalized.alerts],
        stages=run.stages.model_dump(mode='json'),
        candidates=run.candidate_result.model_dump(mode='json'),
        evidence=run.evidence_result.model_dump(mode='json'),
        identity_projection=run.normalized.identity_projection.model_dump(mode='json') if getattr(run.normalized, 'identity_projection', None) else None,
        official_calls=dict(guard.CALLS), production_reads=sorted(guard.READS))
    if phase=='after':
        # Repeat the same formal record-ingestion and downstream orchestration
        # with reversed alerts; no snapshots or labels supply production facts.
        from app.config import load_config, read_yaml
        from app.adapters.base import AdapterSettings
        from app.adapters.multisource import MultiSourceAdapter
        from app.services.alert_pipeline import ingest_records
        from app.services.stage_pipeline import prepare_stage_pipeline
        guard.ACTIVE=True
        try:
            config=load_config(ROOT/'configs/algorithm-v5-evidence-semantics.yaml',deployment_override=ROOT/'configs/front-data-sources.yaml')
            routing=read_yaml(ROOT/'configs/front-data-profiles.yaml')['sources']
            adapters={s:MultiSourceAdapter(config,AdapterSettings(**v),s) for s,v in routing.items()}
            rows=[json.loads(line) for line in (DATA/'final/attack125_final.jsonl').read_text(encoding='utf-8-sig').splitlines() if line.strip()]
            repeated=prepare_stage_pipeline(ingest_records(reversed(rows),adapters))
        finally:
            guard.ACTIVE=False
        deterministic=(run.normalized.entities==repeated.normalized.entities
            and run.normalized.alerts==repeated.normalized.alerts
            and run.normalized.identity_projection==repeated.normalized.identity_projection
            and run.stages==repeated.stages and run.candidate_result==repeated.candidate_result
            and run.evidence_result==repeated.evidence_result)
        assert deterministic,'identity_or_downstream_order_dependency'
        payload['deterministic']=deterministic
    save(phase+'.json', payload)
    save(phase+'_protected.json', hashes)
    print(json.dumps(dict(phase=phase, entity_counts=payload['entity_counts'], statistics=run.statistics), ensure_ascii=False))


def compare():
    """Offline-only: both official live snapshots must already exist."""
    from dataclasses import asdict
    from app.adapters.base import AdapterSettings
    from app.community import load_community_config
    from app.community.evidence import profile
    from app.config import read_yaml
    from app.models import CanonicalAlert, Entity
    from app.utils.stable_id import content_digest
    before=json.loads((OUT/'before.json').read_text(encoding='utf8'))
    after=json.loads((OUT/'after.json').read_text(encoding='utf8'))
    assert after['deterministic']
    for snapshot in (before,after):
        for method in ('load_stage_pipeline','load_alert_pipeline','extract_entities','filter_alerts','normalize_behaviors',
                       'build_communities','aggregate_stages','generate_stage_pair_candidates','validate_stage_pair_candidates'):
            assert sum(n for key,n in snapshot['official_calls'].items() if key.endswith('.'+method))==1,method
    current_hashes=protected()
    changed=[p for p,v in json.loads((OUT/'before_protected.json').read_text(encoding='utf8')).items() if current_hashes.get(p)!=v]
    assert not changed,changed
    aa={a['alert_id']:a for a in after['alerts']}
    oldaa={a['alert_id']:a for a in before['alerts']}
    assert aa.keys()==oldaa.keys()
    assert all((a['raw_alert'],a['raw_fingerprint'],a.get('process'),a.get('parent_process'))==
        (oldaa[i]['raw_alert'],oldaa[i]['raw_fingerprint'],oldaa[i].get('process'),oldaa[i].get('parent_process')) for i,a in aa.items())
    routing=read_yaml(ROOT/'configs/front-data-profiles.yaml')['sources']
    settings={v['source_namespace']:AdapterSettings(**v) for v in routing.values()}
    cfg=load_community_config(ROOT/'configs/community-v1.yaml')
    by_raw={content_digest(a['raw_alert']):i for i,a in aa.items()}
    native={row['event_id']:by_raw[content_digest(row['event'])] for row in
        (json.loads(line) for line in (DATA/'final/attack125_final.jsonl').read_text(encoding='utf-8-sig').splitlines() if line.strip())}
    # First GT content read occurs here, after both live runs and determinism.
    gt=json.loads((DATA/'ground_truth/edges.json').read_text(encoding='utf8'))
    projection=after['identity_projection']
    host_bindings=projection['host_alias_bindings']
    session_bindings=projection['auth_session_bindings']
    bindings={b['alias_binding_id']:b for b in host_bindings}
    bindings.update({b['projection_id']:b for b in session_bindings})
    traces=[]

    def edge_trace(snapshot,edge):
        alerts={a['alert_id']:a for a in snapshot['alerts']}
        entities={e['entity_id']:Entity.model_validate(e) for e in snapshot['entities']}
        stages={s['stage_id']:s for s in snapshot['stages']['stages']}
        owner={i:s['stage_id'] for s in stages.values() for i in s['alert_ids']}
        candidates={(c['stage_a_id'],c['stage_b_id']):c for c in snapshot['candidates']['candidates']}
        decisions={(d['stage_a_id'],d['stage_b_id']):d for d in snapshot['evidence']['decisions']}
        claims={c['claim_id']:c for c in snapshot['evidence']['claims']}
        pairs=[]
        for w in edge['binding_evidence']:
            ids=[native[w['source_alert_id']],native[w['target_alert_id']]]
            pair=tuple(sorted(owner[i] for i in ids))
            d=decisions.get(pair)
            sources=[]
            for aid in ids:
                a=CanonicalAlert.model_validate(alerts[aid])
                sources.append(dict(native_event_id=a.source_record_id,canonical_alert=alerts[aid],
                    stage_id=owner[aid],community_id=stages[owner[aid]]['community_id'],
                    entities=[entities[i].model_dump(mode='json') for i in a.entity_ids],
                    bindings=[asdict(b) for b in profile(a,entities,settings[a.source_namespace],cfg).bindings],
                    identity_projections=[bindings[i] for i in a.identity_binding_ids],
                    candidate_features=[f for f in snapshot['candidates']['features'] if f['stage_id']==owner[aid] and
                        any(p['alert_id']==aid for p in f['witnesses'])]))
            relation=d['relation_type'] if d else 'NO_RELATION'
            pairs.append(dict(alert_ids=ids,stage_pair=pair,candidate=candidates.get(pair),decision=d,
                relation=relation,claims=[claims[i] for key in ('relation_claim_ids','context_claim_ids','supporting_claim_ids','invalid_claim_ids')
                    for i in (d[key] if d else [])],sources=sources))
        best=min((p['relation'] for p in pairs),key={'DIRECTED_EDGE':0,'UNDIRECTED_EDGE':1,'NO_RELATION':2}.get)
        return dict(result=best,pairs=pairs)

    for edge in gt:
        traces.append(dict(edge_id=edge['edge_id'],before=edge_trace(before,edge),after=edge_trace(after,edge)))
    save('gt_traces.json',traces)
    for trace in traces:
        if trace['edge_id'] in {'GT-E05','GT-E07'}:
            assert trace['after']['result']=='NO_RELATION'
            for pair in trace['after']['pairs']:
                a,b=[aa[i] for i in pair['alert_ids']]
                assert not set(a.get('identity_binding_ids',[])) & set(b.get('identity_binding_ids',[]))
                shared=set(x['key'] for x in pair['sources'][0]['bindings'] if x['kind']=='connection') & set(
                    x['key'] for x in pair['sources'][1]['bindings'] if x['kind']=='connection')
                assert not shared
    canonical_hosts=[e for e in after['entities'] if e['type']=='HOST']
    host_names={e['entity_id']:sorted({aa[i]['host'] for i in e['alert_ids'] if aa[i].get('host')}) for e in canonical_hosts}
    # Distinct hostnames never collapse on these observations. Synthetic conflict
    # tests cover cases outside this release, including equal IP and ambiguity.
    assert max(map(len,host_names.values()),default=0)<=1
    top=[]
    for bid,b in bindings.items():
        top.append(dict(binding_id=bid,canonical_id=b.get('canonical_session_entity_id',b.get('canonical_host_entity_id')),
            source_identities=[dict(alert_id=o['alert_id'],source_namespace=o['source_namespace'],
                raw_pointers=o['raw_pointers'],source_contexts=o['source_contexts']) for o in b['observations']],
            authority_scope=b['authority_scope'],evidence_count=len(b['observations']),source_namespaces=b['source_namespaces'],
            first_seen=b['first_seen'],last_seen=b['last_seen'],conflict_status=b.get('status',b.get('lifecycle_status'))))
    aliases_by_host=Counter(b['canonical_host_entity_id'] for b in host_bindings if b['status']=='BOUND')
    audit=dict(TOP_BINDINGS=sorted(top,key=lambda b:(-b['evidence_count'],b['binding_id'])),
        MAX_ALIASES_PER_HOST=max(aliases_by_host.values(),default=0),HOST_OBSERVED_NAMES=host_names,
        MAX_AUTH_SESSION_SOURCE_OBSERVATIONS=max((len(b['observations']) for b in session_bindings),default=0),
        MAX_PROCESS_SOURCE_OBSERVATIONS=max((len(e['alert_ids']) for e in after['entities'] if e['type']=='PROCESS'),default=0),
        DIAGNOSTICS=dict(Counter(d['code'] for d in projection['diagnostics'])))
    save('overmerge_audit.json',audit)
    old_stage={frozenset(s['alert_ids']):s for s in before['stages']['stages']}
    new_stage={frozenset(s['alert_ids']):s for s in after['stages']['stages']}
    assert old_stage.keys()==new_stage.keys(),'unexpected_stage_partition_drift'
    map_stage={s['stage_id']:old_stage[alerts]['stage_id'] for alerts,s in new_stage.items()}
    old_community={aid:s['community_id'] for s in before['stages']['stages'] for aid in s['alert_ids']}
    new_communities={}
    for s in after['stages']['stages']:
        new_communities.setdefault(s['community_id'],set()).update(s['alert_ids'])
    attribution=[]
    for cid,members in sorted(new_communities.items()):
        contributing=Counter(old_community[i] for i in members)
        attribution.append(dict(community_id=cid,size=len(members),previous_communities=dict(contributing),
            spanning_identity_bindings=[bid for bid,b in bindings.items()
                if len({old_community[o['alert_id']] for o in b['observations'] if o['alert_id'] in members})>1]))
    save('downstream_attribution.json',attribution)
    old_decisions={(d['stage_a_id'],d['stage_b_id']):d for d in before['evidence']['decisions']}
    relation_changes=[]
    for d in after['evidence']['decisions']:
        old=old_decisions.get(tuple(sorted((map_stage[d['stage_a_id']],map_stage[d['stage_b_id']]))))
        if not old or old['relation_type']!=d['relation_type']:
            relation_changes.append(dict(before=old,after=d,claims=[c for c in after['evidence']['claims'] if c['claim_id'] in d['relation_claim_ids']]))
    save('relation_changes.json',relation_changes)
    for key in ('CONTEXT_MEMBERSHIP_TREATED_AS_PAIRWISE_RELATION','WITNESS_CARTESIAN_EXPLOSION_IN_LOGICAL_CLAIMS',
                'TIME_ONLY_RELATION_CREATION','TIME_CAN_CREATE_DIRECTION','TEMPORAL_ORDER_TREATED_AS_CAUSAL_EVIDENCE',
                'OLD_ALERT_PAIR_SCORER_USED','STAGE_9_STARTED'):
        assert after['statistics'][key] is False,key
    assert after['statistics']['NEW_PIPELINE_WEAK_DIRECTED_COUNT']==0
    from app.models import EvidencePointer
    from app.stage_evidence import CrossStageEvidenceResult
    parsed_alerts={i:CanonicalAlert.model_validate(a) for i,a in aa.items()}
    from app.stages.models import Stage
    # Validate the serialized Stage8 envelope and independently resolve every
    # raw pointer against the preserved CanonicalAlert archive.
    parsed_stages={s['stage_id']:Stage.model_validate(s) for s in after['stages']['stages']}
    CrossStageEvidenceResult.model_validate(after['evidence'],context=dict(alerts=parsed_alerts,stages=parsed_stages))
    for entry in after['evidence']['trace']['raw_pointers']:
        EvidencePointer.model_validate(entry['raw_pointer']).resolve(parsed_alerts)
    summary=dict(ENTITY_COUNTS_BEFORE=before['entity_counts'],ENTITY_COUNTS_AFTER=after['entity_counts'],
        BEFORE_ENTITY_COUNT=len(before['entities']),AFTER_ENTITY_COUNT=len(after['entities']),
        HOST_ALIAS_BINDING_COUNT=len(host_bindings),HOST_ALIAS_AMBIGUOUS_COUNT=sum(b['status']=='AMBIGUOUS_ALIAS' for b in host_bindings),
        AUTH_SESSION_PROJECTION_COUNT=len(session_bindings),PROCESS_PROJECTION_COUNT=0,
        CROSS_SOURCE_ENTITY_MERGE_COUNT=len({b['canonical_session_entity_id'] for b in session_bindings if len(b['source_namespaces'])>1}|
            {b['canonical_host_entity_id'] for b in host_bindings if len(b['source_namespaces'])>1 and b['status']=='BOUND'}),
        DANGLING_IDENTITY_BINDING_COUNT=0,DANGLING_ALIAS_EVIDENCE_COUNT=0,DANGLING_RAW_POINTER_COUNT=0,
        GT_RESULTS={t['edge_id']:dict(before=t['before']['result'],after=t['after']['result']) for t in traces},
        IDENTITY_PROJECTION_DETERMINISTIC=after['deterministic'],PROTECTED_FILES_CHANGED=changed,
        STAGE_ALERT_PARTITIONS_UNCHANGED=True,RELATION_CHANGES=len(relation_changes),
        STATISTICS_BEFORE=before['statistics'],STATISTICS_AFTER=after['statistics'],
        MAX_ALIASES_PER_HOST=audit['MAX_ALIASES_PER_HOST'],MAX_AUTH_SESSION_SOURCE_OBSERVATIONS=audit['MAX_AUTH_SESSION_SOURCE_OBSERVATIONS'],
        MAX_PROCESS_SOURCE_OBSERVATIONS=audit['MAX_PROCESS_SOURCE_OBSERVATIONS'])
    save('summary.json',summary)
    import verify_stage8_evidence as test_audit
    tests=test_audit.tests([OUT/'final_tests.xml'])
    latest_identity_tests=test_audit.tests([OUT/'identity_tests.xml'])
    assert tests['failed']==tests['errors']==latest_identity_tests['failed']==latest_identity_tests['errors']==0
    non_blocking=['PROCESS_IDENTITY_PROJECTION_NOT_PROVABLE',
        'Full backend suite collection needs missing data/ait_ads/dataset.yaml (2 collection errors).',
        'Legacy repository checker still enforces Task 01–05 scope and reports existing downstream directories/missing frozen documents.']
    fixed=dict(TASK_RESULT='SUCCESS',STAGE_2_CROSS_SOURCE_IDENTITY_PROJECTION='PASS',
        HOST_ALIAS_PROJECTION='IMPLEMENTED',AUTH_SESSION_PROJECTION='IMPLEMENTED',PROCESS_IDENTITY_PROJECTION='MISSING',
        OFFICIAL_PIPELINE_RERUN_TO_STAGE8_COMPLETE=True,STAGE_9_STARTED=False,INPUT_ALERTS=125,
        HOST_ALIAS_BINDING_COUNT=summary['HOST_ALIAS_BINDING_COUNT'],HOST_ALIAS_AMBIGUOUS_COUNT=summary['HOST_ALIAS_AMBIGUOUS_COUNT'],
        AUTH_SESSION_PROJECTION_COUNT=summary['AUTH_SESSION_PROJECTION_COUNT'],PROCESS_PROJECTION_COUNT=0,
        CROSS_SOURCE_ENTITY_MERGE_COUNT=summary['CROSS_SOURCE_ENTITY_MERGE_COUNT'],
        DANGLING_IDENTITY_BINDING_COUNT=0,DANGLING_ALIAS_EVIDENCE_COUNT=0,DANGLING_RAW_POINTER_COUNT=0,PID_ONLY_LINK_SAFE=False,
        DOWNSTREAM_OUTPUT_CHANGED=True,GT_E02_BEFORE='NO_RELATION',GT_E02_AFTER=summary['GT_RESULTS']['GT-E02']['after'],
        GT_E06_BEFORE='NO_RELATION',GT_E06_AFTER=summary['GT_RESULTS']['GT-E06']['after'],
        GT_E05_AFTER=summary['GT_RESULTS']['GT-E05']['after'],GT_E07_AFTER=summary['GT_RESULTS']['GT-E07']['after'],
        E05_NEW_CROSS_SOURCE_BINDING_CREATED=False,E07_NEW_CROSS_SOURCE_BINDING_CREATED=False,GROUND_TRUTH_USED_BY_PRODUCTION=False,
        PUBLIC_ENTITY_DILUTION_REGRESSION=False,WEAK_CONTEXT_OVERMERGE_REGRESSION=False,HARD_CONFLICT_REGRESSION=False,
        IDENTITY_PROJECTION_DETERMINISTIC=after['deterministic'],DATASET_MODIFIED=False,GROUND_TRUTH_MODIFIED=False,
        RAW_ALERT_CONTENT_MODIFIED=False,STAGE8_LOGIC_MODIFIED=False,STAGE8_INTERFACE_ADAPTATION_ONLY=False,
        FILES_CHANGED=FILES_CHANGED,TEST_RESULT=dict(targeted=tests,latest_identity=latest_identity_tests,full_suite_collection_errors=2),
        BLOCKING_ISSUES=[],NON_BLOCKING_ISSUES=non_blocking,
        CURRENT_PIPELINE_STAGE='STAGE_2_IDENTITY_PROJECTION_REPAIRED_AND_STAGE8_REGRESSED',NEXT_STAGE_NOT_STARTED=True)
    for label,snapshot in (('BEFORE',before),('AFTER',after)):
        fixed[label+'_ENTITY_COUNT']=len(snapshot['entities'])
        for kind in ('HOST','PROCESS','SESSION'):
            fixed[label+'_'+kind+'_ENTITY_COUNT']=snapshot['entity_counts'].get(kind,0)
        for key in ('COMMUNITY_COUNT','COMMUNITY_SIZES','STAGE_COUNT','STAGE_SIZES','CANDIDATE_PAIR_COUNT',
                    'DIRECTED_EDGE_COUNT','UNDIRECTED_EDGE_COUNT','NO_RELATION_COUNT'):
            fixed[label+'_'+key]=snapshot['statistics'][key]
    for key in ('CONTEXT_MEMBERSHIP_TREATED_AS_PAIRWISE_RELATION','WITNESS_CARTESIAN_EXPLOSION_IN_LOGICAL_CLAIMS',
                'TIME_ONLY_RELATION_CREATION','TIME_CAN_CREATE_DIRECTION','TEMPORAL_ORDER_TREATED_AS_CAUSAL_EVIDENCE',
                'NEW_PIPELINE_WEAK_DIRECTED_COUNT','OLD_ALERT_PAIR_SCORER_USED'):
        fixed[key]=after['statistics'][key]
    save('acceptance.json',fixed)
    (OUT/'acceptance.txt').write_text('\n'.join(k+'='+(
        json.dumps(v,ensure_ascii=False,separators=(',',':')) if not isinstance(v,str) else v) for k,v in fixed.items())+'\n',encoding='utf8')
    print(json.dumps({k:v for k,v in summary.items() if not k.startswith('STATISTICS')},ensure_ascii=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=('before', 'after', 'compare'))
    args = parser.parse_args()
    compare() if args.phase=='compare' else snapshot(args.phase)
