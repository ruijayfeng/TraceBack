"""Single preregistered development replay; no production integration.

Run from repository root: .venv/Scripts/python -m
evaluation.framework.anchor_semantics.runtime prepare|predict|evaluate|verify
"""
import collections
import gzip
import hashlib
import json
from pathlib import Path
import sys
import time
import yaml
from .model import project, score, SUPPORTED, UNKNOWN, CONTRADICTED, DIMENSIONS
from evaluation.framework.scoring_calibration.model import project as legacy_project, score as legacy_score
from evaluation.framework.formula_design.runtime import guard

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / 'outputs/v5_1_anchor_semantics'
BASE = ROOT / 'outputs/v5_source_bound_observability_final'
CAL = ROOT / 'outputs/v5_scoring_calibration'
POLICY = ROOT / 'evaluation/configs/anchor_semantics.yaml'


def read(path): return json.loads(Path(path).read_text(encoding='utf8'))


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''): h.update(block)
    return h.hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)+'\n', encoding='utf8')


def rows(path):
    with gzip.open(path, 'rt', encoding='utf8') as stream:
        for line in stream: yield json.loads(line)


def dump(stream, value):
    stream.write(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n')


def feature(kind, strength, reliability, *, anchor=None, role='generic', family='entity'):
    return dict(name='entity.'+kind if family == 'entity' else kind, family=family,
        state='OBSERVED_SUPPORT', strength=strength, reliability=reliability,
        hot=False, role=role, parent_only=False, anchor_kind=anchor)


def stress_inputs(repetitions):
    """Explicit feature/projection witnesses, not a vendor-native dataset.

    These cases exercise the semantic boundary in isolation. Existing development
    replay below provides real Adapter/Entity/Candidate provenance. Labels live in
    a separate return value and are not passed to project or score.
    """
    inputs, answers = [], []
    scenarios = [
        ('identifier_reuse', False, 'SESSION', 'epoch_conflict'),
        ('long_lived_session', False, 'SESSION', 'context'),
        ('persistent_connection', False, 'SESSION', 'context'),
        ('shared_login_context', False, 'SESSION', 'context'),
        ('worker_pool', False, 'PROCESS', 'task_conflict'),
        ('multi_action_process', False, 'PROCESS', 'task_conflict'),
        ('sensor_local_collision', False, 'SESSION', 'scope_conflict'),
        ('pid_reuse', False, 'PROCESS', 'pid_reuse'),
        ('unobserved_distinct_tasks', False, 'PROCESS', 'sparse'),
        ('short_request_continuation', True, 'SESSION', 'task'),
        ('transaction_continuation', True, 'SESSION', 'task'),
        ('legitimate_long_session', True, 'SESSION', 'sparse'),
        ('legitimate_login_context', True, 'SESSION', 'sparse'),
        ('process_child_lineage', True, 'PROCESS', 'direct'),
        ('cross_source_attested', True, 'DIRECT', 'direct'),
        ('request_worker_binding', True, 'PROCESS', 'direct'),
        ('missing_task_multiple_weak_signals', True, 'NONE', 'sparse'),
        ('sparse_content_continuation', True, 'PROCESS', 'sparse'),
    ]
    for scenario, positive, kind, mode in scenarios:
        for i in range(repetitions):
            # Disjoint identities/times for repeatability; neither reaches arithmetic.
            aid, bid = f'dev_{scenario}_{i}_a', f'dev_{scenario}_{i}_b'
            context = dict(scope='application-scope', role='session')
            if mode == 'task': context.update(epoch='life', task_id='task', role='request',
                start='2026-01-01T00:00:00Z', end='2026-01-01T00:01:00Z')
            if mode == 'epoch_conflict': context.update(epoch='life-a')
            if mode == 'task_conflict': context.update(task_id='task-a', role='worker')
            a = dict(alert_id=aid, timestamp='2026-01-01T00:00:10Z', raw_alert={'session_context':context})
            b = dict(alert_id=bid, timestamp='2026-01-01T00:00:20Z', raw_alert={'session_context':dict(context)})
            if mode == 'epoch_conflict': b['raw_alert']['session_context']['epoch'] = 'life-b'
            if mode == 'scope_conflict': b['raw_alert']['session_context']['scope'] = 'other-sensor'
            if mode == 'task_conflict': b['raw_alert']['session_context']['task_id'] = 'task-b'
            fs = [feature('HOST', .9, .7), feature('time.distance', .98-i*.001, .1, family='time')]
            bindings, entities = [], {}
            if kind in {'SESSION', 'PROCESS'} and mode != 'pid_reuse':
                fs.append(feature(kind, .9, .8, anchor=kind.lower()))
                eid = 'entity-context'
                binding = dict(entity_id=eid, type=kind, parent_only=False,
                               scope=json.dumps(dict(identity_kind='request' if mode=='task' else
                                                    'auth_session', namespace='asset-scope')))
                bindings.append(binding)
                entities[eid] = dict(value=json.dumps(dict(host='asset', pid=25,
                    start_time='2026-01-01T00:00:00Z')))
            if mode == 'direct':
                fs.append(feature('topology.attested_relation', .95, 1., anchor='attested_relation',
                                  role='direct', family='relation'))
            if mode in {'sparse', 'task_conflict'}:
                fs.append(feature('ACCOUNT', .95, .75))
            env = dict(features=fs, valid=True, gate=dict(passed=True, hard_contradiction=False,
                duplicate_observation=False), conflict_penalty=0., duplicate_penalty=0.)
            inputs.append(dict(id=f'{scenario}:{i}', env=env, bindings=bindings, a=a, b=b,
                entities=entities, behavior=.9 if mode in {'task', 'sparse', 'direct', 'task_conflict'} else .4,
                candidate=True, source_pair=['waf', 'waf'] if i % 2 else ['waf', 'edr'],
                anchor_type=kind))
            answers.append(dict(id=f'{scenario}:{i}', positive=positive, scenario=scenario))
    return inputs, answers


def prepare():
    if (OUT/'manifest.json').exists(): raise ValueError('immutable_preregistration_exists')
    policy = yaml.safe_load(POLICY.read_text(encoding='utf8'))
    required={'version','DEVELOPMENT_ONLY','deployment','REFERENCE_THRESHOLD','TARGET_GT_RECALL',
        'TARGET_HN_REJECTION','TARGET_WORST_MARGIN','TARGET_CLASS_BALANCE','acceptance','formula','stress'}
    formula_keys={'unknown_compatibility','identity_reliability','identity_rarity_floor','time_floor',
        'parent_only_factor','weak_ceiling','minimum_weak_groups','behavior_minimum','task_kinds',
        'context_kinds','context_roles','task_roles','evidence_paths'}
    if set(policy)!=required or set(policy['formula'])!=formula_keys: raise ValueError('unknown_or_missing_config_key')
    for key in ['unknown_compatibility','identity_reliability','identity_rarity_floor','time_floor',
                'parent_only_factor','weak_ceiling','behavior_minimum']:
        value=policy['formula'][key]
        if type(value) not in {int,float} or not 0<=value<=1:raise ValueError('invalid_policy_number:'+key)
    if policy['REFERENCE_THRESHOLD'] != .65 or policy['deployment'] or not policy['DEVELOPMENT_ONLY']:
        raise ValueError('research_boundary')
    protected = {}
    for folder, pattern in [('backend/app', '*.py'), ('configs', '*.yaml'), ('docs', '*.md')]:
        for p in sorted((ROOT/folder).rglob(pattern)): protected[str(p.relative_to(ROOT))] = sha(p)
    protected['AGENTS.md'] = sha(ROOT/'AGENTS.md')
    # Never open, hash or enumerate the old independent-validation directory.
    for folder in [BASE, CAL, ROOT/'outputs/v5_formula_design', ROOT/'outputs/v5_evidence_semantics_final']:
        for p in sorted(folder.iterdir()):
            if p.is_file(): protected[str(p.relative_to(ROOT))] = sha(p)
    inputs = [BASE/'blind_A/canonical.jsonl.gz', BASE/'blind_A/entities.jsonl.gz',
              BASE/'blind_A/candidate_pairs.json', CAL/'predictions/member_features.jsonl.gz']
    for p in inputs: protected[str(p.relative_to(ROOT))] = sha(p)
    code = {str(p.relative_to(ROOT)):sha(p) for p in sorted(Path(__file__).parent.glob('*.py'))}
    code[str(POLICY.relative_to(ROOT))] = sha(POLICY)
    stress, answers = stress_inputs(policy['stress']['repetitions'])
    save(OUT/'stress_input.json', stress); save(OUT/'stress_answers.json', answers)
    save(OUT/'manifest.json', dict(status='PREREGISTERED_BEFORE_SCORING', policy=policy,
        policy_sha256=sha(POLICY), implementation=code, protected_files=protected,
        input_files=[str(p.relative_to(ROOT)) for p in inputs],
        stress_input_sha256=sha(OUT/'stress_input.json'), stress_answers_sha256=sha(OUT/'stress_answers.json'),
        split='existing Final Dataset development + synthetic feature stress',
        stress_limitations='Feature-level stress, no independent data or vendor-format coverage claim.',
        historical_failure='V5_EXACT_ANCHOR_OVER_CORRELATED; user-supplied aggregate only',
        original_formula='evaluation/framework/scoring_calibration/model.py',
        original_formula_sha256=sha(ROOT/'evaluation/framework/scoring_calibration/model.py'),
        old_policy_sha256=sha(ROOT/'evaluation/configs/scoring_calibration.yaml'),
        ground_truth_loaded_for_scoring=False, threshold_calibration=False))
    print('PREREGISTERED', len(stress), flush=True)


def verify():
    manifest = read(OUT/'manifest.json')
    if sha(ROOT/'evaluation/configs/scoring_calibration.yaml')!=manifest['old_policy_sha256']:
        raise ValueError('original_policy_changed')
    for name, expected in (manifest['protected_files'] | manifest['implementation']).items():
        if sha(ROOT/name) != expected: raise ValueError('immutable_file_changed:'+name)
    for name in ['stress_input', 'stress_answers']:
        if sha(OUT/(name+'.json')) != manifest[name+'_sha256']: raise ValueError('stress_modified')
    return manifest


def predict():
    manifest = verify()
    if (OUT/'prediction_seal.json').exists() or (OUT/'evaluation_started.json').exists():
        raise ValueError('single_preregistered_run_already_sealed')
    policy = manifest['policy']['formula']; threshold = manifest['policy']['REFERENCE_THRESHOLD']
    oldpolicy = yaml.safe_load((ROOT/'evaluation/configs/scoring_calibration.yaml').read_text(encoding='utf8'))
    inputs = [ROOT/p for p in manifest['input_files']]
    destination = OUT/'predictions'; destination.mkdir(exist_ok=False)
    expected_digest = read(BASE/'blind_A/receipt.json')['candidate_digest']
    started = time.perf_counter(); count = candidates = admitted = legacy_admitted = 0
    seen = set(); previous = None; best = oldbest = fallback = None
    with guard(inputs+[OUT/'stress_input.json'], destination) as (events, reads):
        alerts = {r['alert_id']:r for r in rows(inputs[0])}
        entities = {r['entity_id']:r for r in rows(inputs[1])}
        expected = {tuple(r) for r in read(inputs[2])}
        with gzip.open(destination/'members.jsonl.gz','wt',encoding='utf8',compresslevel=1) as members, \
             gzip.open(destination/'candidates.jsonl.gz','wt',encoding='utf8',compresslevel=1) as pairs:
            def flush():
                nonlocal candidates, admitted, legacy_admitted
                if previous is None: return
                candidates += 1
                chosen = best or fallback
                admitted += bool(best and best['score'] >= threshold)
                legacy_admitted += bool(oldbest and oldbest['score'] >= threshold)
                dump(pairs,dict(support_key=previous,result=chosen,legacy=oldbest,valid_winner=best is not None))
            for row in rows(inputs[3]):
                key = tuple(row['support_key'])
                if key != previous:
                    flush()
                    if key in seen or key not in expected: raise ValueError('candidate_order_or_set_changed')
                    seen.add(key); previous=key; best=oldbest=fallback=None
                count += 1
                a,b = [alerts[x] for x in row['support_pair']]
                pseudo = dict(support_pair=row['support_pair'], valid=row['valid'], evidence={'evidence_v5':row['baseline']})
                env, bindings = legacy_project(pseudo, alerts, entities)
                enriched, bound = project(env, bindings, a, b, entities, row['values']['behavior'], policy)
                result = score(enriched,policy)
                if count <= 128 and score({**enriched,'features':list(reversed(enriched['features'])),
                    'anchors':list(reversed(enriched['anchors']))},policy) != result:
                    raise ValueError('order_nondeterministic')
                tie = [a['timestamp'], b['timestamp'], *row['support_pair']]
                old = legacy_score(env,oldpolicy,'C')
                result.update(support_pair=row['support_pair'],tie=tie,bindings=bound,
                    source_pair=sorted([row['source_a'],row['source_b']]),
                    anchor_type='+'.join(sorted({x['feature'] for x in result['anchors']})) or 'NONE',
                    observable_dimensions=row['observable_dimensions'], original_values=row['values'],
                    original_validity=row['valid'], original_rejection_codes=row['rejection_codes'])
                if fallback is None or (-result['score'],tie)<(-fallback['score'],fallback['tie']): fallback=result
                if result['gate'] and (best is None or (-result['score'],tie)<(-best['score'],best['tie'])): best=result
                old.update(tie=tie,support_pair=row['support_pair'])
                if old['gate'] and (oldbest is None or (-old['score'],tie)<(-oldbest['score'],oldbest['tie'])): oldbest=old
                dump(members,dict(support_key=key,result=result))
                if count % 30000 == 0: print('SCORED',count,'SECONDS',round(time.perf_counter()-started),flush=True)
            flush()
        if seen != expected or digest(sorted(seen)) != expected_digest or (candidates,count)!=(240621,241464):
            raise ValueError('incomplete_candidate_or_member_replay')
        stress = []
        for item in read(OUT/'stress_input.json'):
            env,bound = project(item['env'],item['bindings'],item['a'],item['b'],item['entities'],item['behavior'],policy)
            stress.append(dict(id=item['id'],candidate=item['candidate'],source_pair=item['source_pair'],
                anchor_type=item['anchor_type'],result=score(env,policy),bindings=bound))
        save(destination/'stress.json',stress)
        save(destination/'receipt.json',dict(candidates=candidates,members=count,admitted=admitted,
            legacy_admitted=legacy_admitted,candidate_digest=expected_digest,ground_truth_read=False,
            read_paths=sorted(reads),denied=events,seconds=time.perf_counter()-started,
            guard='Python audit tripwire, not OS sandbox'))
    save(OUT/'prediction_seal.json',dict(status='SEALED_BEFORE_DEVELOPMENT_GT_JOIN',
        manifest_sha256=sha(OUT/'manifest.json'),files={str(p.relative_to(OUT)):sha(p) for p in destination.iterdir()}))
    print('PREDICTIONS_SEALED',candidates,count,admitted,flush=True)


def verify_predictions():
    m=verify();seal=read(OUT/'prediction_seal.json')
    if seal['manifest_sha256']!=sha(OUT/'manifest.json'):raise ValueError('preregistration_changed')
    for name,h in seal['files'].items():
        if sha(OUT/name)!=h:raise ValueError('predictions_changed')
    return m


def metrics(items, threshold):
    positives=[r for r in items if r['positive']]; negatives=[r for r in items if not r['positive']]
    low=min((r['result']['score'] for r in positives),default=None)
    high=max((r['result']['score'] for r in negatives),default=None)
    accept=lambda r:r['candidate'] and r['result']['gate'] and r['result']['score']>=threshold
    return dict(GT=len(positives),HN=len(negatives),
        candidate_recall=sum(r['candidate'] for r in positives)/len(positives) if positives else None,
        admission_recall=sum(accept(r) for r in positives)/len(positives) if positives else None,
        hn_rejection=sum(not accept(r) for r in negatives)/len(negatives) if negatives else None,
        min_gt_score=low,max_hn_score=high,worst_margin=low-high if low is not None and high is not None else None,
        positive_class_fraction=len(positives)/len(items) if items else None,
        false_rejected_gt=[r['id'] for r in positives if not accept(r)],
        false_admitted_hn=[r['id'] for r in negatives if accept(r)])


def stratify(items, threshold):
    report={}
    for dimension in ['anchor_type','source_pair','scenario','source_mode']:
        groups=collections.defaultdict(list)
        for r in items:
            name=('+'.join(r['source_pair']) if dimension=='source_pair' else
                  'same_source' if len(set(r['source_pair']))==1 else 'cross_source') if dimension in {'source_pair','source_mode'} else r[dimension]
            groups[name].append(r)
        report[dimension]={k:metrics(v,threshold) for k,v in sorted(groups.items())}
    return report


def evaluate():
    manifest=verify_predictions()  # Must precede every answer/label read.
    if (OUT/'evaluation_started.json').exists(): raise ValueError('already_evaluated')
    save(OUT/'evaluation_started.json',dict(prediction_seal_sha256=sha(OUT/'prediction_seal.json'),
        development_only=True,old_independent_validation_opened=False))
    gt=read(BASE/'gt_edge_evaluation.json'); hn=read(BASE/'hard_negative_evaluation.json')
    wanted={}
    for positive,records in [(True,gt['edges']),(False,hn['pairs'])]:
        for i,r in enumerate(records):
            wanted[tuple(r['support_key']) if r['support_key'] else ('absent',positive,i)]=dict(
                id=r.get('edge_id',r.get('pair_id',str(i))),positive=positive,
                scenario=str(r.get('scenario_id','development_GT' if positive else 'development_HN')))
    results={}
    for row in rows(OUT/'predictions/candidates.jsonl.gz'):
        key=tuple(row['support_key'])
        if key in wanted:results[key]=row['result']
    missing=dict(score=0.,gate=False,anchors=[],source_pair=['unknown','unknown'],anchor_type='NONE')
    existing=[dict(**v,candidate=k in results,result=results.get(k,missing),
        source_pair=results.get(k,missing)['source_pair'],anchor_type=results.get(k,missing)['anchor_type']) for k,v in wanted.items()]
    answers={r['id']:r for r in read(OUT/'stress_answers.json')}
    stress=[dict(**row,positive=answers[row['id']]['positive'],scenario=answers[row['id']]['scenario'])
            for row in read(OUT/'predictions/stress.json')]
    threshold=manifest['policy']['REFERENCE_THRESHOLD']; policy=manifest['policy']
    summary={}; failures=[]
    for name,items in [('existing_development',existing),('synthetic_feature_stress',stress)]:
        summary[name]=dict(overall=metrics(items,threshold),by=stratify(items,threshold))
        bad=set(summary[name]['overall']['false_rejected_gt']+summary[name]['overall']['false_admitted_hn'])
        failures.extend(dict(dataset=name,**r) for r in items if r['id'] in bad)
    values=[s['overall'] for s in summary.values()]
    over_restrictive=any(s['admission_recall']<policy['TARGET_GT_RECALL'] for s in values)
    over_correlated=any(s['hn_rejection']<policy['TARGET_HN_REJECTION'] for s in values)
    separation=all(s['worst_margin']>=policy['TARGET_WORST_MARGIN'] and s['candidate_recall']==1. for s in values)
    balanced=summary['synthetic_feature_stress']['overall']['positive_class_fraction']==policy['TARGET_CLASS_BALANCE']
    class_pass=all((s['admission_recall'] is None or s['admission_recall']>=policy['acceptance']['per_positive_scenario_recall'])
        and (s['hn_rejection'] is None or s['hn_rejection']>=policy['acceptance']['per_negative_scenario_rejection'])
        for ds in summary.values() for s in ds['by']['scenario'].values())
    result=('V5_1_ANCHOR_SEMANTICS_OVER_RESTRICTIVE' if over_restrictive else
        'V5_1_ANCHOR_SEMANTICS_STILL_OVER_CORRELATED' if over_correlated else
        'V5_1_ANCHOR_SEMANTICS_REPAIR_ACCEPTED_FOR_NEW_VALIDATION' if separation and balanced and class_pass else
        'V5_1_REPAIR_INCONCLUSIVE')
    save(OUT/'evaluation_summary.json',dict(TASK_RESULT=result,NEW_INDEPENDENT_VALIDATION_READY=
        result.endswith('ACCEPTED_FOR_NEW_VALIDATION'),development_only=True,reference_threshold=threshold,
        datasets=summary,over_restrictive=over_restrictive,over_correlated=over_correlated,
        separation_pass=separation,class_balance_pass=balanced,per_scenario_pass=class_pass,
        limitations=['Synthetic feature stress is developer-authored, not a new vendor-native dataset.',
                    'Existing development has only seven positive edges; no real-world accuracy claim.']))
    save(OUT/'failure_decomposition.json',failures)
    save(OUT/'labeled_decomposition.json',dict(existing_development=existing,synthetic_feature_stress=stress))
    print(result,flush=True)
    print(json.dumps({k:v['overall'] for k,v in summary.items()}),flush=True)


if __name__=='__main__':
    {'prepare':prepare,'predict':predict,'evaluate':evaluate,'verify':verify_predictions}[sys.argv[1]]()
