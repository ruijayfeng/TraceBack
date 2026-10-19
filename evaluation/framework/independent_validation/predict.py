"""Two truth-denied workers: native preprocessing, then frozen research scoring."""
import gzip
import json
import sys
import time
from . import ROOT, OUT, DATA
from .seal import verify
from evaluation.framework.scoring_calibration.snapshot import read, save, sha, digest_map


def rows(path):
    with gzip.open(path, 'rt', encoding='utf8') as stream:
        for line in stream:
            yield json.loads(line)


def dump(stream, value):
    stream.write(json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False)+'\n')


def require_pre_evaluation():
    if (OUT/'evaluation_started.json').exists():
        raise ValueError('scorer_forbidden_after_evaluation')
    verify()


def prepare():
    require_pre_evaluation()
    sys.path.insert(0, str(ROOT/'backend'))
    from app.adapters.multisource import MultiSourceAdapter
    from app.adapters.base import AdapterSettings
    from app.entities.extraction import extract_entities
    from app.dedup import deduplicate
    from app.correlation.edges import run_correlation
    from app.correlation.index import AlertIndex
    from app.services.storage import restore_config
    from evaluation.framework.v4_semisynthetic_baseline.blind import replay_guard
    import ctypes.wintypes
    spec=read(OUT/'validation_formula_seal.json')
    cfg=restore_config(spec['config']['algorithm'])
    settings={k:AdapterSettings(**v) for k,v in spec['config']['sources'].items()}
    adapters={k.rsplit('.',1)[1]:MultiSourceAdapter(cfg,v,k.rsplit('.',1)[1]) for k,v in settings.items()}
    destination=OUT/'preprocessing';destination.mkdir(exist_ok=False)
    input_path=DATA/'input/alerts.jsonl';input_hash=sha(input_path)
    tick=time.perf_counter()
    with replay_guard(input_path,destination) as (events,reads):
        alerts=[adapters[r['source_type']].convert_record(r) for r in (json.loads(line) for line in input_path.open(encoding='utf8'))]
        alerts.sort(key=lambda a:a.alert_id)
        dedupe=deduplicate(alerts,cfg,settings)
        if not dedupe.is_complete: raise ValueError('dedupe_incomplete')
        extracted=extract_entities(alerts,settings)
        alerts,entities=extracted.alerts,extracted.entities
        for name,objects in [('canonical',alerts),('entities',entities),('dedupe',dedupe.groups)]:
            with gzip.open(destination/(name+'.jsonl.gz'),'wt',encoding='utf8',compresslevel=1) as f:
                for obj in objects: f.write(obj.canonical_json()+'\n')
        with gzip.open(destination/'diagnostics.jsonl.gz','wt',encoding='utf8',compresslevel=1) as f:
            result=run_correlation(alerts,dedupe.groups,entities,cfg,settings,diagnostic_sink=lambda r:dump(f,r),
                progress=lambda r:print(json.dumps(r),flush=True))
        if not result.record.is_complete: raise ValueError('candidate_replay_incomplete')
        index=AlertIndex(alerts,dedupe.groups,entities)
        save(destination/'candidate_pairs.json',sorted([list(c.support_key) for c in result.candidates.pairs]))
        save(destination/'owner.json',index.owner)
        save(destination/'record.json',result.record.model_dump(mode='json'))
        save(destination/'frequency_snapshot.json',index.frequency_snapshot())
        save(destination/'receipt.json',dict(alerts=len(alerts),entities=len(entities),groups=len(dedupe.groups),
            candidates=len(result.candidates.pairs),production_admitted=len(result.edges),
            input_sha256=input_hash,reads=sorted(reads),denied=events,labels_read=False,seconds=time.perf_counter()-tick))
    save(OUT/'preprocessing_seal.json',dict(files={str(p):sha(p) for p in sorted(destination.iterdir())},
        input_path=str(input_path),input_sha256=input_hash,labels_read=False))
    print('PREPROCESSING_SEALED',len(alerts),len(result.candidates.pairs),flush=True)


def anchor_details(env, bindings, result, policy):
    eligible=[]
    for f in env['features']:
        if f['family'] not in {'entity','relation'} or f['state']!='OBSERVED_SUPPORT' or not f['anchor_kind'] or f['hot'] or f['strength']<policy['minimum_anchor_strength']:
            continue
        q=f['strength']*f['reliability'] if f['anchor_kind']=='attested_relation' else policy['anchor_reliability']*(policy['anchor_rarity_floor']+(1-policy['anchor_rarity_floor'])*f['strength'])
        eligible.append((q,f['name'],f))
    chosen=min(eligible,key=lambda x:(-x[0],x[1])) if eligible else None
    f=chosen[2] if chosen else None
    kind=f['anchor_kind'] if f else 'no-anchor'
    scopes=[b for b in bindings if (kind=='session' and b['type']=='SESSION') or (kind=='process' and b['type']=='PROCESS')]
    return dict(has_anchor=result['anchor'],anchor_type=kind,anchor_strength=f['strength'] if f else None,
        anchor_reliability=(f['reliability'] if kind=='attested_relation' else policy['anchor_reliability']) if f else None,
        anchor_scope=scopes,anchor_hot=f['hot'] if f else None,
        anchor_context={k:result['groups'].get(k,0.) for k in ('context','identity')},
        anchor_selected=f['name'] if f else None,anchor_value=chosen[0] if chosen else 0.,
        why_anchor_qualified='observed support, not hot, strength >= frozen minimum; exact typed scope / complete non-parent-only instance / verified direct relation' if f else None,
        context_floor=policy['context_floor'],all_qualified_types=result['anchor_types'])


def blind():
    require_pre_evaluation()
    if (OUT/'prediction_seal.json').exists(): raise ValueError('predictions_already_sealed')
    from evaluation.framework.formula_design.runtime import guard
    from evaluation.framework.scoring_calibration.model import project,score
    spec=read(OUT/'validation_formula_seal.json');policy=spec['parameters']
    pre=read(OUT/'preprocessing_seal.json')
    for p,h in pre['files'].items():
        if sha(p)!=h: raise ValueError('preprocessing_changed')
    source=OUT/'preprocessing'
    paths=[source/n for n in ('canonical.jsonl.gz','entities.jsonl.gz','diagnostics.jsonl.gz','candidate_pairs.json')]
    destination=OUT/'validation_predictions';destination.mkdir(exist_ok=False)
    policies={'frozen':policy}
    for key,multipliers in spec['local_sensitivity'].items():
        for multiplier in multipliers:
            policies[f'{key}*{multiplier}']={**policy,key:policy[key]*multiplier}
    worker_sources={str(p):sha(p) for p in (ROOT/'evaluation/framework/independent_validation').glob('*.py')}
    expected=None;seen=set();previous=None;best={};baseline_best=None;members=0;metamorphic=0
    with guard(paths,destination) as (events,reads):
        alerts={a['alert_id']:a for a in rows(paths[0])};entities={e['entity_id']:e for e in rows(paths[1])}
        expected={tuple(p) for p in read(paths[3])}
        with gzip.open(destination/'candidates.jsonl.gz','wt',encoding='utf8',compresslevel=1) as pairs, \
             gzip.open(destination/'members.jsonl.gz','wt',encoding='utf8',compresslevel=1) as member_out:
            def flush():
                if previous is not None:
                    dump(pairs,dict(support_key=previous,variants=best,production=baseline_best))
            for row in rows(paths[2]):
                if row['stage']!='member_score': continue
                pair=tuple(row['support_key'])
                if pair!=previous:
                    flush()
                    if pair in seen or pair not in expected: raise ValueError('member_order_or_candidate_invalid')
                    seen.add(pair);previous=pair;best={};baseline_best=None
                members+=1
                a,b=[alerts[i] for i in row['support_pair']]
                tie=(a['timestamp'],b['timestamp'],a['alert_id'],b['alert_id'])
                env,bindings=project(row,alerts,entities)
                results={name:score(env,p,'C') for name,p in policies.items()}
                if members<=64:
                    if score({**env,'features':list(reversed(env['features']))},policy,'C')!=results['frozen']:
                        raise ValueError('order_invariance_failed')
                    metamorphic+=1
                baseline=dict(score=row['score'],gate=bool(row['valid']),support_pair=row['support_pair'],tie=tie)
                if baseline_best is None or (not baseline['gate'],-baseline['score'],tie)<(not baseline_best['gate'],-baseline_best['score'],baseline_best['tie']): baseline_best=baseline
                for name,r in results.items():
                    value=dict(score=r['score'],gate=r['gate'],admitted=r['gate'] and r['score']>=.65,
                        support_pair=row['support_pair'],tie=tie)
                    if name=='frozen':
                        value.update(result=r,anchor=anchor_details(env,bindings,r,policy),
                            source_a=a['raw_alert'].get('source_type',a['source_type']),source_b=b['raw_alert'].get('source_type',b['source_type']),
                            rejection_codes=row['rejection_codes'],typed_bindings=bindings,
                            evidence_features=row['evidence']['evidence_v5']['features'])
                    if name not in best or (not value['gate'],-value['score'],tie)<(not best[name]['gate'],-best[name]['score'],best[name]['tie']): best[name]=value
                dump(member_out,dict(support_key=pair,support_pair=row['support_pair'],environment=env,
                    bindings=bindings,results=results,values=row['values'],rejection_codes=row['rejection_codes']))
            flush()
        if seen!=expected: raise ValueError('incomplete_candidate_scoring')
        save(destination/'receipt.json',dict(candidates=len(seen),members=members,reads=sorted(reads),denied=events,
            labels_read=False,order_metamorphic_pairs=metamorphic,variants=list(policies),
            sensitivity_precedes_labels=True,scorer_not_reexecuted_after_evaluation=True))
    verify()
    save(OUT/'prediction_seal.json',dict(status='SEALED_BEFORE_LABELS',files={str(p):sha(p) for p in sorted(destination.iterdir())},
        worker_sources=worker_sources,formula_seal_sha256=sha(OUT/'validation_formula_seal.json'),
        parameter_seal_sha256=sha(OUT/'validation_parameter_seal.json'),preprocessing_seal_sha256=sha(OUT/'preprocessing_seal.json'),labels_read=False))
    print('ALL_PREDICTIONS_SEALED',len(seen),members,flush=True)


if __name__=='__main__': {'prepare':prepare,'blind':blind}[sys.argv[1]]()
