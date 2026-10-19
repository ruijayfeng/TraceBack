"""Reproducible real-alert v5 validation, isolated from production and truth.

Run from repository root with Python 3.11. All writes stay under OUT. No labels,
scenarios, production snapshots, config updates or domain objects are published.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from contextlib import contextmanager
import argparse
import hashlib
import heapq
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
import v5_design_diagnostic as d
import v5_validation_evidence as ev
from app.adapters import AMinerAdapter, WazuhAdapter
from app.adapters.base import AdapterSettings
from app.services.storage import restore_config
from build_ait_ads_slices import records

OUT = ROOT/'outputs/v5_evidence_validation'
PREVIOUS = ROOT/'outputs/v5_design_diagnostic'
VERSION = 'v5-evidence-validation-1'


def save(name, value):
    d.atomic_json(OUT/name, value)


def freeze(start=False):
    config, receipt, _ = d.load_frozen_config()
    if config.mapping_digest != 'aba87d612711cc4cb67998df9604b62b61a3fb72b01c165d1745594b8a538658':
        raise ValueError('mapping_digest_changed')
    if config.algorithm.score.correlation_threshold != .65:
        raise ValueError('reference_threshold_changed')
    previous = d.read(PREVIOUS/'protected_before.json')
    # Existing frozen receipt, including accepted execution-equivalence changes.
    changed = {p:dict(expected=h, actual=d.file_digest(ROOT/p)) for p,h in previous.items()
               if not (ROOT/p).is_file() or d.file_digest(ROOT/p)!=h}
    if changed:
        save('frozen_state.json', dict(status='FAIL', changed=changed))
        raise ValueError('prior_frozen_files_changed')
    historical = d.read(PREVIOUS/'manifest.json')
    artifacts = {p:d.file_digest(PREVIOUS/p) for p in historical['files']}
    mismatch = {p:dict(expected=h,actual=artifacts[p]) for p,h in historical['files'].items() if artifacts[p]!=h}
    if mismatch:
        save('frozen_state.json', dict(status='FAIL', diagnostic_artifacts_changed=mismatch))
        raise ValueError('existing_diagnostic_artifact_changed')
    protected = {p.relative_to(ROOT).as_posix():d.file_digest(p)
        for base, glob in [('backend/app','*.py'),('configs','*.yaml')]
        for p in sorted((ROOT/base).rglob(glob))}
    protected.update(previous)
    for p in sorted(PREVIOUS.iterdir()):
        if p.is_file(): protected[p.relative_to(ROOT).as_posix()]=d.file_digest(p)
    for p in sorted((ROOT/'data/cptc_2018/raw/suricata').glob('*.gz')):
        protected[p.relative_to(ROOT).as_posix()]=d.file_digest(p)
    for scene in ('russellmitchell_dev_small','fox_validation_small'):
        for p in sorted((ROOT/'data/ait_ads/slices'/scene).rglob('*.json')):
            protected[p.relative_to(ROOT).as_posix()]=d.file_digest(p)
    baseline=OUT/'protected_before.json'
    if start and not baseline.exists(): save('protected_before.json',protected)
    if not baseline.exists(): raise ValueError('pre_task_baseline_missing')
    before=d.read(baseline)
    if protected!=before: raise ValueError('protected_state_changed_during_validation')
    git=subprocess.run(['git','status','--short'],cwd=ROOT,capture_output=True,text=True)
    state=dict(status='PASS', algorithm_version=d.correlation_version(config), threshold=.65,
        v4_config_hash=config.config_hash, mapping_digest=config.mapping_digest,
        git_status=git.stdout.strip() if git.returncode==0 else 'UNAVAILABLE_NO_GIT_METADATA',
        protected_file_count=len(protected),protected_files_changed=False,
        existing_v5_artifacts=artifacts, dataset_hashes={p:h for p,h in protected.items() if p.startswith('data/')},
        frozen_implementation_receipt='outputs/correlation_v4_small/FREEZE_MANIFEST.json',
        production_v4_modified='NO', production_v5_implemented='NO')
    save('frozen_state.json',state)
    return config


def raw_values(raw):
    metadata=raw.get('alert',{})
    return dict(timestamp=raw.get('timestamp'),src_ip=raw.get('src_ip'),dst_ip=raw.get('dest_ip',raw.get('dst_ip')),
        src_port=raw.get('src_port'),dst_port=raw.get('dest_port',raw.get('dst_port')),
        protocol=raw.get('proto'),flow_id=raw.get('flow_id'),rule_id=metadata.get('signature_id'),
        signature=metadata.get('signature'),domain=raw.get('http',{}).get('hostname',raw.get('tls',{}).get('sni')),
        url=raw.get('http',{}).get('url'))


def lightweight_cptc():
    cached=OUT/'cptc_lightweight_profiles.json'
    if cached.exists():
        previous=d.read(cached)
        if set(previous)=={'t1','t2','t5','t7','t8','t9'} and all(
            p['sha256']==d.file_digest(ROOT/f'data/cptc_2018/raw/suricata/suricata_alert_{name}.json.gz')
            for name,p in previous.items()):
            d.log('lightweight_profiles_reused',hash_verified=True)
            return previous
    profiles={}
    for partition in ('t1','t2','t5','t7','t8','t9'):
        path=ROOT/f'data/cptc_2018/raw/suricata/suricata_alert_{partition}.json.gz'
        counts=Counter(); fields=Counter();n=0;lo=hi=None
        for rec in d.read_cptc_file(path):
            if rec.error: raise ValueError(rec.error)
            vals=raw_values(rec.eve); n+=1
            counts[ev.evidence_profile(vals)['evidence_completeness']]+=1
            fields.update(f for f,v in vals.items() if ev.present(v))
            stamp=vals['timestamp'];lo=stamp if lo is None else min(lo,stamp);hi=stamp if hi is None else max(hi,stamp)
        profiles[partition]=dict(raw_count=n,selected_count=0,sha256=d.file_digest(path),
            evidence_completeness=dict(counts),field_presence=dict(fields),time_range=[lo,hi],
            profile_kind='LIGHTWEIGHT_RAW_PREREQUISITES_NOT_CANONICAL_SCORING',
            selection='No extra slice: native schema already covered by existing t5 10k; no scoring on full partitions.',
            limitation='No adapter/entity run on full partitions. Category/optional unextracted raw fields are not inferred.')
        save('cptc_lightweight_profiles.json',profiles)
        d.log('lightweight_profile',partition=partition,raw_count=n,distribution=dict(counts))
    return profiles


def ait_dataset(scene):
    base=ROOT/'data/ait_ads/slices'/scene
    manifest=d.read(base/'slice_manifest.json')
    from app.services.datasets import load_dataset
    parent='russellmitchell' if scene.startswith('russellmitchell') else 'fox'
    # Use already confirmed source deployment and dataset-specific ingestion
    # mappings; scoring remains the exact frozen v4 snapshot.
    loaded=load_dataset(ROOT,scene_id=parent,config_version='v4')
    settings={s['source_namespace']:AdapterSettings(**s) for s in manifest['adapter_settings'].values()}
    alerts={};locators={};raw_count=0
    for source in ('aminer','wazuh'):
        spec=manifest['adapter_settings'][source]
        setting=settings[spec['source_namespace']]
        adapter=(AMinerAdapter if source=='aminer' else WazuhAdapter)(loaded.config,setting)
        path=base/'raw'/f'{source}.json'
        for ordinal,raw in enumerate(records(path),1):
            raw_count+=1
            a=adapter.convert(raw);alerts[a.alert_id]=a
            locators[a.alert_id]=dict(path=path.relative_to(ROOT).as_posix(),ordinal=ordinal,
                source=source,source_namespace=a.source_namespace,raw_fingerprint=a.raw_fingerprint)
    if len(alerts)!=manifest['canonical_alert_count']:raise ValueError('slice_adapter_count_changed')
    return list(alerts.values()),settings,locators,dict(raw_count=raw_count,selected_count=len(alerts),
        selection='existing deterministic midpoint slice; complete slice retained',seed=None,
        role='validation_no_parameter_selection' if parent=='fox' else 'development',
        input_hashes={p.relative_to(ROOT).as_posix():d.file_digest(p) for p in (base/'slice_manifest.json',base/'raw/aminer.json',base/'raw/wazuh.json')},
        ingestion_config_hash=loaded.config.config_hash,ingestion_mapping_digest=loaded.config.mapping_digest)


@contextmanager
def scorer_for(alerts, settings, config):
    with d.bounded_execution(OUT/'spill'):
        groups=d.deduplicate(alerts,config,settings).groups
        extracted=d.extract_entities(alerts,settings)
        index=d.AlertIndex(extracted.alerts,groups,extracted.entities)
        scorer=d.CorrelationScorer(index,config,settings)
        yield scorer


def propose(scorer, previous=False):
    """Bounded index proposals for a REVIEW SET, not production candidate recall.

    Pair nomination never reads semantic labels or scenario metadata. Controls
    intentionally include non-admitted/out-of-window pairs and same-group
    observations. Every scored row is an entire original pair, never pieced data.
    """
    result=defaultdict(set)
    def add(a,b,stratum):
        if a!=b:result[tuple(sorted((a,b)))].add(stratum)
    if previous:
        tops=d.read(PREVIOUS/'top_pairs.json')
        for key,rows in tops.items():
            for r in rows:
                add(r['alert_a']['alert_id'],r['alert_b']['alert_id'],'prior_top100_'+key)
        # Sample all frozen candidates uniformly by stable hash, including low
        # and middle ranks. Reuse exact archived nomination provenance.
        sample=[]
        with (PREVIOUS/'candidate_pairs.jsonl').open(encoding='utf8') as stream:
            for line in stream:
                row=json.loads(line);ids=(row['source_alert_id'],row['target_alert_id'])
                rank=int(hashlib.sha256(('|'.join(ids)).encode()).hexdigest(),16)
                item=(-rank,ids)
                if len(sample)<600:heapq.heappush(sample,item)
                elif item>sample[0]:heapq.heapreplace(sample,item)
        for _,(a,b) in sample:add(a,b,'archived_candidate_hash600')
    alerts=sorted(scorer.index.alerts.values(),key=lambda a:(scorer.index.times[a.alert_id],a.alert_id))
    buckets=defaultdict(list)
    for a in alerts:
        keys=[('source',a.source_namespace,a.src_ip),('target',a.source_namespace,a.dst_ip),
              ('signature',a.source_namespace,a.rule_id,a.signature),
              ('transport',a.source_namespace,a.dst_port,ev.field_values(a)['protocol'])]
        keys.extend(('entity',e) for e in a.entity_ids)
        for key in keys:
            if all(x is not None for x in key):buckets[key].append(a.alert_id)
    strata=defaultdict(set)
    def control(a,b,name):
        if a!=b:strata[name].add(tuple(sorted((a,b))))
    # Near-time disjoint actors, same source-IP, same target, same signature,
    # resource/identity, and transport buckets; at most eight look-aheads.
    for pos,a in enumerate(alerts):
        for b in alerts[pos+1:pos+9]:
            va={a.src_ip,a.dst_ip}-{None};vb={b.src_ip,b.dst_ip}-{None}
            shared=set(a.entity_ids)&set(b.entity_ids)
            gap=abs(scorer.index.times[a.alert_id]-scorer.index.times[b.alert_id])/1e6
            if gap<=60 and va and vb and va.isdisjoint(vb) and not shared:
                control(a.alert_id,b.alert_id,'N1_time_disjoint')
    for key,ids in sorted(buckets.items(),key=lambda kv:str(kv[0])):
        for pos,aid in enumerate(ids):
            a=scorer.index.alerts[aid]
            for bid in ids[pos+1:pos+4]:
                b=scorer.index.alerts[bid]
                if key[0]=='signature' and a.src_ip and b.src_ip and a.src_ip!=b.src_ip and a.dst_ip!=b.dst_ip:
                    control(aid,bid,'N2_same_signature_disjoint')
                if key[0]=='source' and a.dst_ip and b.dst_ip and a.dst_ip!=b.dst_ip:
                    control(aid,bid,'N3_shared_source_multi_target')
                if key[0]=='target' and a.src_ip and b.src_ip and a.src_ip!=b.src_ip:
                    control(aid,bid,'N4_shared_target_multi_source')
                if key[0]=='entity':
                    entity=key[1]
                    if scorer.evidence_evaluator.hot(entity):control(aid,bid,'N5_hot_entity')
                    else:control(aid,bid,'context_index')
                if key[0]=='transport' and not(set(a.entity_ids)&set(b.entity_ids)):
                    control(aid,bid,'N7_transport_only')
            if len(ids)>1:
                bid=ids[-1]
                gap=abs(scorer.index.times[aid]-scorer.index.times[bid])/1e6
                if gap>scorer.algorithm.candidate.max_window_seconds:control(aid,bid,'N8_cross_time')
    for representative,members in scorer.index.groups.items():
        if len(members)>1:
            for aid in members[1:4]:control(members[0],aid,'N6_same_observation_group')
    for name,pairs in sorted(strata.items()):
        # Fixed pre-score budget independent of outcomes/labels; deterministic.
        chosen=sorted(pairs,key=lambda p:(hashlib.sha256('|'.join(p).encode()).hexdigest(),p))[:250]
        for a,b in chosen:add(a,b,name)
    return result,{name:dict(proposed=len(pairs),selected=min(250,len(pairs))) for name,pairs in sorted(strata.items())}


def run():
    OUT.mkdir(parents=True,exist_ok=True)
    config=freeze(start=True)
    # Exact existing names/parameters, loaded and equality checked before data.
    import yaml
    policy=yaml.safe_load((PREVIOUS/'diagnostic_policy.yaml').read_text(encoding='utf8'))
    if policy!=d.design():raise ValueError('diagnostic_policy_code_diverged')
    save('experiment_policy.json',dict(version=VERSION,formula_candidates=policy,
        profile_definition=ev.evidence_profile.__doc__,review_budget_per_control_per_dataset=250,
        candidate_hash_sample=600,development_and_validation_no_tuning=True,
        ground_truth_used_for_scoring='NO'))
    with d.truth_guard(ROOT):
        lightweight=lightweight_cptc()
        profiles={};caps=[];all_cards=[];all_views={};manifests={'MEDIUM':[],'SPARSE':[]}
        for name in ('cptc_t5_dev_10k','russellmitchell_dev_small','fox_validation_small'):
            d.log('dataset_start',dataset=name)
            if name=='cptc_t5_dev_10k':
                # Same ingestion/scoring split as previous diagnostic.
                ingestion=d.load_cptc_dataset(ROOT).config
                saved=d.read(ROOT/'outputs/cptc_2018_step3a_t5/recipe.json')
                settings={k:AdapterSettings(**v) for k,v in saved['config_snapshot']['sources'].items()}
                adapter=d.SuricataAdapter(ingestion,next(iter(settings.values())))
                alerts=[];locators={}
                for rec in d.read_cptc_file(d.DEV):
                    if rec.error:raise ValueError(rec.error)
                    a=adapter.convert(rec.eve);alerts.append(a)
                    locators[a.alert_id]=dict(path=d.DEV.relative_to(ROOT).as_posix(),ordinal=rec.ordinal,
                        source='suricata',source_namespace=a.source_namespace,raw_fingerprint=a.raw_fingerprint)
                meta=dict(raw_count=len(alerts),selected_count=len(alerts),selection='reuse existing frozen 10k deterministic development slice',
                    seed=None,input_hashes={d.DEV.relative_to(ROOT).as_posix():d.file_digest(d.DEV)},
                    ingestion_config_hash=ingestion.config_hash,ingestion_mapping_digest=ingestion.mapping_digest,role='development')
            else: alerts,settings,locators,meta=ait_dataset(name)
            dist,observed,rows=ev.profile_alerts(alerts,settings,name)
            caps+=observed
            profile_path=f'{name}_evidence_profiles.jsonl'
            with (OUT/profile_path).open('w',encoding='utf8',newline='\n') as h:
                for row in sorted(rows,key=lambda r:r['alert_id']):h.write(json.dumps(row,sort_keys=True)+'\n')
            for a in alerts:
                level=ev.evidence_profile(ev.field_values(a))['evidence_completeness']
                if level in manifests:
                    manifests[level].append(dict(dataset=name,alert_id=a.alert_id,**locators[a.alert_id],
                        evidence_profile=ev.evidence_profile(ev.field_values(a))))
            profiles[name]=dict(**meta,completeness=dict(dist),source_distribution=dict(Counter(a.source_type.value for a in alerts)),
                signature_distribution=dict(Counter(a.signature for a in alerts)),
                entity_field_distribution={f:dict(Counter(str(getattr(a,f)) for a in alerts if getattr(a,f) is not None))
                    for f in ('src_ip','dst_ip','host','account')},
                time_range=[str(min(a.timestamp for a in alerts)),str(max(a.timestamp for a in alerts))],
                profile_rows_ref=profile_path,selected_identity_digest=d.content_digest(sorted([a.alert_id,a.raw_fingerprint] for a in alerts)))
            with scorer_for(alerts,settings,config) as scorer:
                proposals,selection=propose(scorer,previous=name=='cptc_t5_dev_10k')
                profiles[name]['review_pair_selection']=selection
                profiles[name]['representative_count']=scorer.index.N
                for n,(ids,strata) in enumerate(sorted(proposals.items()),1):
                    card,view=ev.make_card(ids,scorer,policy,name,strata)
                    all_cards.append(card);all_views[card['candidate_id']]=view
                    if n%500==0:d.log('review_scoring',dataset=name,pairs=n,total=len(proposals))
                d.log('dataset_complete',dataset=name,distribution=dict(dist),review_pairs=len(proposals))
            save('dataset_profiles.json',dict(scored_slices=profiles,lightweight_only=lightweight))
            save('source_capability_matrix.json',dict(status='OBSERVED_VALIDATION_ARTIFACT',profiles=caps))
            save('review_cards_checkpoint.json',all_cards)
        save('evidence_completeness_distribution.json',{k:v['completeness'] for k,v in profiles.items()})
        for level,rows in manifests.items():
            if rows:save(f'{level.lower()}_sample_manifest.json',dict(count=len(rows),selection='all naturally occurring canonical records in unchanged slices',records=rows))
        save('source_capability_observed.json',dict(status='OBSERVED_VALIDATION_ARTIFACT',profiles=caps,
            production_registry=False,unavailable_by_source_attestations=0))
        from v5_validation_report import finish
        finish(all_cards,all_views,profiles,caps,policy,OUT)
    freeze()
    artifact_hashes={p.name:d.file_digest(p) for p in sorted(OUT.iterdir()) if p.is_file() and p.name!='manifest.json'}
    manifest=dict(version=VERSION,files=artifact_hashes,ground_truth_used_for_scoring='NO',
        production_v4_modified='NO',production_v5_implemented='NO',
        source_hashes={p:d.file_digest(ROOT/p) for p in ('scripts/v5_evidence_validation.py','scripts/v5_validation_evidence.py','scripts/v5_validation_report.py')},
        previous_manifest_sha256=d.file_digest(PREVIOUS/'manifest.json'),
        policy_sha256=d.file_digest(OUT/'experiment_policy.json'),results=d.read(OUT/'formula_freeze_evidence.json'))
    save('manifest.json',manifest)
    d.log('complete',result=manifest['results']['task_result'])


def refresh_reports():
    """Replay scoring from captured numeric evidence; no re-selection/tuning."""
    freeze()
    policy=d.read(OUT/'experiment_policy.json')['formula_candidates']
    if policy!=d.design():raise ValueError('policy_changed')
    cards=d.read(OUT/'review_cards_checkpoint.json')
    views={}
    for card in cards:
        view=ev.replay_view(card)
        actual=ev.compare(view,policy)
        for k in d.CANDIDATES:
            if abs(actual[k]['score']-card['prototypes'][k]['score'])>1e-12 or actual[k]['admitted']!=card['prototypes'][k]['admitted']:
                raise ValueError('card_score_replay_changed:'+card['candidate_id'])
        views[card['candidate_id']]=view
    profile_doc=d.read(OUT/'dataset_profiles.json')
    profiles=profile_doc['scored_slices']
    for name,meta in profiles.items():
        if name=='cptc_t5_dev_10k':
            settings=d.read(ROOT/'outputs/cptc_2018_step3a_t5/recipe.json')['config_snapshot']['sources']
        else:
            original=d.read(ROOT/f'data/ait_ads/slices/{name}/slice_manifest.json')['adapter_settings']
            settings={s['source_namespace']:s for s in original.values()}
        cfg,_,_=d.load_frozen_config()
        meta['source_settings_snapshot']=settings
        meta['scoring_algorithm_snapshot']=cfg.snapshot
        meta['effective_scoring_config_hash']=d.content_digest(dict(algorithm=cfg.snapshot,sources=settings))
        meta['stored_breakdown_config_hash_scope']='frozen base algorithm; effective deployment hash recorded separately'
    save('dataset_profiles.json',profile_doc)
    from v5_validation_report import finish
    with d.truth_guard(ROOT):
        finish(cards,views,profiles,d.read(OUT/'source_capability_matrix.json')['profiles'],policy,OUT)
    save('reproducibility.json',dict(status='PASS',captured_pairs_replayed=len(cards),
        all_A_D_scores_equal_within=1e-12,admissions_equal=True,
        limitation='Score-only replay from captured observations; no full candidate universe or independent human labels claimed.',
        semantic_score_digest=d.content_digest([[r['candidate_id'],r['v4_score'],
            {k:dict(score=r['prototypes'][k]['score'],admitted=r['prototypes'][k]['admitted']) for k in d.CANDIDATES}]
            for r in sorted(cards,key=lambda r:r['candidate_id'])])))
    freeze()
    manifest=d.read(OUT/'manifest.json')
    manifest.update(files={p.name:d.file_digest(p) for p in sorted(OUT.iterdir()) if p.is_file() and p.name!='manifest.json'},
        source_hashes={p:d.file_digest(ROOT/p) for p in ('scripts/v5_evidence_validation.py','scripts/v5_validation_evidence.py','scripts/v5_validation_report.py','backend/tests/test_v5_evidence_validation.py')},
        results=d.read(OUT/'formula_freeze_evidence.json'))
    save('manifest.json',manifest)
    d.log('report_replay_complete',pairs=len(cards))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--verify-freeze',action='store_true')
    parser.add_argument('--refresh-reports',action='store_true')
    args=parser.parse_args()
    if args.verify_freeze:
        freeze();print('Frozen state PASS')
    elif args.refresh_reports:refresh_reports()
    else:run()
