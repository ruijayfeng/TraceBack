"""Pre-formula experiment. Blind worker and post-seal evaluation are separate processes."""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
from dataclasses import replace
import json
from pathlib import Path
import sys

from evaluation.framework.v4_semisynthetic_baseline.common import (ROOT, DATASET, INPUT,
    VERSION, read, save, sha, inventory, verify_inventory)

OUT = ROOT/'outputs/v5_preformula_candidate_recovery'
BEFORE = ROOT/'outputs/v4_semisynthetic_baseline'
DEPLOYMENT = ROOT/'evaluation/configs/v5_preformula_deployment.yaml'
FORMULA = ('backend/app/correlation/scoring.py', 'backend/app/correlation/evidence.py',
    'backend/app/correlation/evidence_v3.py', 'backend/app/correlation/evidence_v4.py',
    'backend/app/correlation/conflicts.py', 'backend/app/correlation/edges.py',
    'backend/app/models/scoring.py', 'backend/app/models/correlation_v3.py',
    'backend/app/dedup/grouping.py', 'backend/app/dedup/observation.py',
    'backend/app/chains/assembly.py', 'backend/app/chains/direction.py',
    'configs/algorithm-v4.yaml')


def prepare():
    import yaml
    from app.adapters.base import AdapterSettings
    from app.services.storage import restore_config
    from app.utils.stable_id import content_digest
    if (OUT/'preparation.json').exists():
        raise ValueError('single_use_preparation_already_frozen')
    deployment = yaml.safe_load(DEPLOYMENT.read_text(encoding='utf8'))
    baseline = read(BEFORE/'preparation.json')
    cfg = restore_config(baseline['algorithm'])
    if cfg.algorithm.score.correlation_threshold != .65 or cfg.algorithm.version != 'v4':
        raise ValueError('formula_not_frozen_v4')
    source_settings = {}
    for ns, value in baseline['sources'].items():
        old = AdapterSettings(**value)
        source_settings[ns] = replace(old, network_namespace=deployment['network_namespace'],
            asset_namespace=deployment['asset_namespace'],
            account_realm=deployment['account_realm'] if ns != 'suricata' else None,
            semantic_profile=deployment['wazuh_semantic_profile'] if ns != 'suricata' else None).snapshot()
    initial = read(OUT/'production_before.json')
    unchanged = {p:sha(ROOT/p) for p in FORMULA}
    if any(initial[p]!=v for p,v in unchanged.items()):
        raise ValueError('frozen_formula_component_changed')
    prepared = {'input':str(INPUT), 'input_sha256':sha(INPUT), 'algorithm':baseline['algorithm'],
        'sources':source_settings, 'deployment_contract':deployment,
        'deployment_file_sha256':sha(DEPLOYMENT), 'formula_components':unchanged,
        'implementation_before_blind':inventory(ROOT,production=True),
        'historical_artifacts': {p.relative_to(BEFORE).as_posix():sha(p) for p in BEFORE.glob('*.json')},
        'projection_contract_version':'role-aware-v1', 'ground_truth_loaded':False}
    prepared['run_config_hash'] = content_digest({'algorithm':cfg.snapshot,'sources':source_settings})
    save(OUT/'preparation.json',prepared)
    save(OUT/'deployment_contract.json',{'contract':deployment,'sources':source_settings,
        'sha256':content_digest(deployment),'user_authorization':'2026-10-16 namespace clarification',
        'no_shared_session_scope':True})


def blind():
    # Import no GT adapter/evaluator. The reused worker's read allowlist admits
    # only this dataset JSONL and the current output directory during algorithms.
    from evaluation.framework.v4_semisynthetic_baseline import blind as worker
    from app.correlation.edges import peak_memory_mb
    prepared=read(OUT/'preparation.json')
    if sha(INPUT)!=prepared['input_sha256'] or sha(DEPLOYMENT)!=prepared['deployment_file_sha256']:
        raise ValueError('input_or_contract_changed')
    if verify_inventory(ROOT,prepared['implementation_before_blind'],production=True)['status']!='PASS':
        raise ValueError('implementation_changed_after_preparation')
    worker.OUT=OUT
    worker.run()
    manifest=read(OUT/'blind_run_manifest.json')
    manifest.update(projection_contract_version='role-aware-v1',
        deployment_contract_sha256=sha(OUT/'deployment_contract.json'),
        preparation_sha256=sha(OUT/'preparation.json'), formula_components=prepared['formula_components'],
        peak_memory_mb=peak_memory_mb(), dataset_read_only=True)
    save(OUT/'blind_run_manifest.json',manifest)


def evaluate():
    # The imported truth adapter checks this seal BEFORE reading any sidecar.
    from evaluation.framework.v4_semisynthetic_baseline.artifacts import rows, require_sealed
    from evaluation.framework.v4_semisynthetic_baseline import truth as truth_adapter
    from evaluation.framework.v4_semisynthetic_baseline.metrics import pair_key, ranking, correct_correlation_witness
    seal=require_sealed(OUT)
    prepared=read(OUT/'preparation.json')
    if sha(OUT/'preparation.json')!=seal['preparation_sha256']:
        raise ValueError('preparation_changed_after_blind')
    for p,digest in prepared['formula_components'].items():
        if sha(ROOT/p)!=digest: raise ValueError('frozen_formula_changed:'+p)
    dataset_integrity=verify_inventory(DATASET,read(OUT/'dataset_before.json'))
    if dataset_integrity['status']!='PASS': raise ValueError('dataset_modified')
    for name,digest in prepared['historical_artifacts'].items():
        if sha(BEFORE/name)!=digest: raise ValueError('historical_evidence_modified')
    alerts={r['alert_id']:r for r in rows(OUT/'blind/canonical.jsonl.gz')}
    old_alerts={r['alert_id']:r for r in rows(BEFORE/'blind/canonical.jsonl.gz')}
    if set(alerts)!=set(old_alerts) or any(a['raw_alert']!=old_alerts[k]['raw_alert'] for k,a in alerts.items()):
        raise ValueError('raw_or_alert_identity_changed')
    truth_adapter.OUT=OUT
    truth_adapter.require_sealed=lambda:require_sealed(OUT)
    truth=truth_adapter.load(alerts)
    owners=read(OUT/'blind/owner.json'); old_owners=read(BEFORE/'blind/owner.json')
    before_audit={r['gt_edge_id']:r for r in read(BEFORE/'gt_edge_audit.json')}
    target_pairs=set().union(*truth['witnesses'].values())
    scores, details, candidates, old_candidates={}, {}, {}, set()
    for r in rows(BEFORE/'blind/diagnostics.jsonl.gz'):
        if r['stage']=='candidate': old_candidates.add(tuple(r['support_key']))
    hard_candidates, explicit_scored=set(),set()
    bridges=defaultdict(lambda:{'pairs':set(),'new_pairs':set(),'entities':set(),'role_pairs':Counter(),'source_pairs':Counter(),'windows':set()})
    entities={r['entity_id']:r for r in rows(OUT/'blind/entities.jsonl.gz')}
    old_entities={r['entity_id']:r for r in rows(BEFORE/'blind/entities.jsonl.gz')}
    freq={r['entity_id']:r['df'] for r in read(OUT/'blind/frequency_snapshot.json')['entities']}
    summary=read(OUT/'blind/correlation_summary.json')
    # Audit existing candidate witnesses from canonical occurrences; no scoring
    # or candidate function may be called in this post-hoc evaluator.
    def witnesses(a,b):
        la,rb=defaultdict(set),defaultdict(set)
        for o in a['entity_occurrences']:la[o['entity_id']].add(o['role'])
        for o in b['entity_occurrences']:rb[o['entity_id']].add(o['role'])
        for eid in sorted(la.keys()&rb.keys()):
            kind=entities[eid]['type']; roles=la[eid]|rb[eid]
            label=None
            if kind=='IP' and 'monitored_host_ip' in roles:
                label='monitored_host_ip' if 'monitored_host_ip' in la[eid]&rb[eid] else 'network_monitored_ip'
            elif kind=='HOST' and (a.get('semantic_observations') or b.get('semantic_observations')):label='local_host'
            elif kind=='ACCOUNT' and roles-{'account'}:label='account_roles'
            if label:yield label,eid,sorted(la[eid]),sorted(rb[eid])
    for r in rows(OUT/'blind/diagnostics.jsonl.gz'):
        if r['stage']=='candidate':
            k=tuple(r['support_key']); candidates[k]=r
            if set(owners[h] for h in truth['hard_ids'])&set(k):hard_candidates.add(k)
            # Candidate evidence binds actual members; never attribute a bridge
            # from unrelated members of the same dedupe group.
            seen=set()
            for e in r['evidence']:
                a,b=(alerts[i] for i in e['alert_ids'])
                for label,eid,lr,rr in witnesses(a,b):
                    if eid != e['entity_id']:
                        continue
                    identity=(label,eid,tuple(lr),tuple(rr),tuple(sorted((a['source_type'],b['source_type']))))
                    if identity in seen:continue
                    seen.add(identity)
                    audit=bridges[label];audit['pairs'].add(k);audit['entities'].add(eid)
                    if k not in old_candidates:audit['new_pairs'].add(k)
                    audit['role_pairs'][str((lr,rr))]+=1
                    audit['source_pairs'][str(sorted((a['source_type'],b['source_type'])))]+=1
                    audit['windows'].add(e['effective_window_seconds'])
        elif r['stage']=='member_score':
            k=pair_key(*r['support_pair']);scores[k]=r['score']
            if k in target_pairs:details[k]=r
            if k in truth['negative_pairs']:explicit_scored.add(k)
    if len(candidates)!=summary['scored_candidate_count'] or summary['resource_truncated_count']:
        raise ValueError('candidate_completeness_failed')
    formal=list(rows(OUT/'blind/correlation_edges.jsonl.gz'))
    rank=ranking(scores,truth['witnesses']);recovery=[]
    for edge in truth['gt']['edges']:
        eid=edge['edge_id'];pair=next(iter(truth['witnesses'][eid]));member=details.get(pair)
        source=truth['ids'][edge['witness_alert_ids']['from']];target=truth['ids'][edge['witness_alert_ids']['to']]
        candidate=candidates.get(pair_key(owners[source],owners[target])) if owners[source]!=owners[target] else None
        nominated_eids={e['entity_id'] for e in candidate['evidence']} if candidate else set()
        obs=[o for o in witnesses(alerts[source],alerts[target]) if o[1] in nominated_eids]
        def entity_view(a):
            return [{'entity':entities[o['entity_id']],'role':o['role'],'raw_pointer':o['raw_pointer']} for o in a['entity_occurrences']]
        def old_entity_view(a):
            return [{'entity':old_entities[o['entity_id']],'role':o['role'],'raw_pointer':o['raw_pointer']} for o in a['entity_occurrences']]
        recovery.append({'gt_edge_id':eid, 'raw_semantic_witness':edge['equality_witnesses'],
            'before':{'candidate_generated':before_audit[eid]['candidate_generated'],
                      'score_computed':before_audit[eid]['score_computed'],'score':before_audit[eid]['score'],
                      'projection':before_audit[eid]['raw_join_projection'],
                      'canonical_source_entities':old_entity_view(old_alerts[source]),
                      'canonical_target_entities':old_entity_view(old_alerts[target])},
            'after':{'canonical_source_entities':entity_view(alerts[source]),'canonical_target_entities':entity_view(alerts[target]),
                'bridge_used':[o[0] for o in obs], 'bridge_entities':[o[1] for o in obs],
                'candidate_generated':candidate is not None,'candidate_provenance':candidate,
                'score_computed':member is not None,'score':member['score'] if member else None,
                'admitted':any(correct_correlation_witness(e,{pair}) for e in formal),
                'score_evidence':member,'ranking':rank['edges'][eid]},
            'cause':root_cause(eid, candidate is not None)})
    n=len(candidates);old_n=len(old_candidates);new=set(candidates)-old_candidates
    removed=old_candidates-set(candidates)
    hard_scores=[s for p,s in scores.items() if set(p)&truth['hard_ids']]
    old_hard=read(BEFORE/'hard_negative_audit.json')
    bridge_rows=[]
    posting_groups=defaultdict(set)
    for aid,alert in alerts.items():
        for occurrence in alert['entity_occurrences']:
            posting_groups[occurrence['entity_id']].add(owners[aid])
    policy=prepared['algorithm']['candidate']
    for label in ['network_monitored_ip','monitored_host_ip','local_host','account_roles']:
        r=bridges[label]; ids=r['entities']
        bridge_rows.append({'bridge_type':label,'candidate_count_before':0,'candidate_count_after':len(r['pairs']),
            'global_candidate_count_before':old_n,'global_candidate_count_after':n,
            'candidate_pairs_using_bridge':len(r['pairs']),'new_candidate_pairs_using_bridge':len(r['new_pairs']),
            'hard_negative_candidate_pairs_using_bridge':len(r['pairs'] & hard_candidates),
            'new_hard_negative_candidate_pairs_using_bridge':len(r['new_pairs'] & hard_candidates),
            'unique_entity_count':len(ids),'high_frequency_entity_count':sum(freq[e]>=policy['hot_entity_min_count'] and freq[e]/summary['representative_alert_count']>=policy['hot_entity_ratio'] for e in ids),
            'largest_entity_bucket_groups':max((len(posting_groups[e]) for e in ids),default=0),
            'potential_pairs_before_time_and_capacity_upper_bound':sum(len(posting_groups[e])*(len(posting_groups[e])-1)//2 for e in ids),
            'potential_pair_bound_may_overlap':True,
            'candidate_expansion_ratio':None, 'expansion_ratio_status':'new_role_channel_has_zero_baseline_denominator',
            'global_candidate_expansion_ratio':n/old_n, 'time_window':sorted(r['windows']),
            'source_pairs':dict(r['source_pairs']),'role_pairs':dict(r['role_pairs']),
            'unique_new_pairs_not_additive':True})
    bridged_new=set().union(*(v['new_pairs'] for v in bridges.values()))
    growth={'candidate_count_before':old_n,'candidate_count_after':n,'candidate_growth_ratio':n/old_n,
            'relative_increase':(n-old_n)/old_n,'added_unique_pairs':len(new),'removed_unique_pairs':len(removed),
            'new_pairs_with_bridge_witness':len(bridged_new),
            'new_pairs_from_existing_channels_with_shared_namespaces':len(new-bridged_new),
            'resource_truncated_count':summary['resource_truncated_count'],'capacity_policy_unchanged':True}
    hard={'hard_negative_count':30,'hard_negative_candidate_count_before':old_hard['hard_negative_candidate_count'],
          'hard_negative_candidate_count_after':len(hard_candidates),
          'explicit_negative_pairs_scored_before':old_hard['explicit_negative_candidate_count'],
          'explicit_negative_pairs_scored_after':len(explicit_scored),
          'hard_negative_max_score':max(hard_scores) if hard_scores else None,
          'explicit_negative_max_score':max((scores[p] for p in explicit_scored),default=None),
          'hard_negative_candidate_growth_ratio':len(hard_candidates)/old_hard['hard_negative_candidate_count'],
          'hard_negative_alert_exposure':[{'alert_id':aid,
             'candidate_count_before':sum(old_owners[aid] in p for p in old_candidates),
             'candidate_count_after':sum(owners[aid] in p for p in candidates)} for aid in sorted(truth['hard_ids'])],
          'candidate_growth_attributable_to_bridge':len(bridged_new & hard_candidates),
          'new_hard_negative_candidates_total':len(new & hard_candidates),
          'new_hard_negative_candidates_existing_channels_with_shared_namespaces':len((new-bridged_new)&hard_candidates),
          'selectivity_status':'REVIEW_REQUIRED',
          'note':'Background remains unlabeled; increased negative exposure is not an admission or measured background false-positive rate.'}
    got=sum(r['after']['candidate_generated'] for r in recovery);scored=sum(r['after']['score_computed'] for r in recovery)
    result={'TASK_RESULT':'V5_PREFORMULA_CANDIDATE_RECOVERY_PARTIAL','DATASET_INTEGRITY':'PASS','GROUND_TRUTH_LEAKAGE':False,
        'GT_EDGES':6,'CANDIDATE_GT_EDGES_BEFORE':1,'CANDIDATE_GT_EDGES_AFTER':got,
        'SCORED_GT_EDGES_BEFORE':1,'SCORED_GT_EDGES_AFTER':scored,
        'ADMITTED_GT_EDGES':sum(r['after']['admitted'] for r in recovery),'CANDIDATE_RECALL':got/6,
        'CANDIDATE_COUNT_BEFORE':old_n,'CANDIDATE_COUNT_AFTER':n,'CANDIDATE_GROWTH_RATIO':n/old_n,
        'HARD_NEGATIVE_CANDIDATES_BEFORE':old_hard['hard_negative_candidate_count'],
        'HARD_NEGATIVE_CANDIDATES_AFTER':len(hard_candidates),'HARD_NEGATIVE_MAX_SCORE':hard['hard_negative_max_score'],
        'V4_SCORE_FORMULA_MODIFIED':'NO','THRESHOLD':.65,'PROJECTION_CONTRACT_MODIFIED':'YES','CANDIDATE_POLICY_MODIFIED':'YES',
        'V5_FORMULA_DESIGN_GATE':'NOT_READY','runtime_seconds':seal['total_seconds'],'peak_memory_mb':seal['peak_memory_mb'],
        'FULL_REGRESSION_STATUS':'PENDING_REPORT','candidate_selectivity_review_required':True}
    for name,value in [('gt_edge_recovery',recovery),('before_after_projection',recovery),('candidate_bridge_audit',bridge_rows),
                       ('candidate_growth',growth),('hard_negative_safety',hard),('ranking_metrics',rank),('summary',result),('dataset_integrity',dataset_integrity)]:
        save(OUT/(name+'.json'),value)
    print(json.dumps(result),flush=True)


def root_cause(eid, recovered):
    causes={
        'GT-E01':['preexisting_candidate; scoring failure is outside this repair'],
        'GT-E02':['adapter projection: monitored agent IP absent','role modeling: monitored IP missing','namespace: no shared network contract'],
        'GT-E03':['adapter projection: agent host and audit login identity absent','entity extraction: no canonical observations for raw-only fields'],
        'GT-E04':['adapter projection: target account absent','namespace: account realm/network not shared','role modeling: account subject roles absent'],
        'GT-E05':['adapter projection: monitored host and audit login account absent','namespace: asset/account isolation'],
        'GT-E06':['adapter projection: monitored host IP absent','namespace: network scope isolation','candidate policy: no compatible monitored-role observation']}
    return {'layers':causes[eid], 'true_unobservable_for_nomination':False,
            'recovered':recovered,'unobservable_causal_fields':'No request/session/process lineage is invented; nomination is not causal observability.'}


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('stage',choices=['prepare','blind','evaluate'])
    args=parser.parse_args();globals()[args.stage]()
