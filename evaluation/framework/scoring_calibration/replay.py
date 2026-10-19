"""Complete member replay on a fixed candidate set, under a truth-denying guard."""
import gzip
import hashlib
import json
import sys
import time
import yaml
from . import ROOT, BASE, OUT, POLICY
from .snapshot import read, save, sha, digest_map
from .model import project, score
from evaluation.framework.formula_design.runtime import guard


def rows(path):
    with gzip.open(path, 'rt', encoding='utf8') as stream:
        for line in stream:
            yield json.loads(line)


def dump(stream, value):
    stream.write(json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False) + '\n')


def run():
    if (OUT / 'prediction_seal.json').exists() or (OUT / 'evaluation_started.json').exists():
        raise ValueError('predictions_already_sealed_or_evaluated')
    seal = read(OUT / 'baseline/seal.json')
    paths = [BASE / 'blind_A' / name for name in
             ('canonical.jsonl.gz', 'entities.jsonl.gz', 'diagnostics.jsonl.gz', 'candidate_pairs.json')]
    for p in paths:
        if sha(p) != seal['protected_files'][str(p)]:
            raise ValueError('sealed_input_changed')
    policy = yaml.safe_load(POLICY.read_text(encoding='utf8'))
    if policy['deployment'] is not False or policy['selection']['independent_test_available'] is not False:
        raise ValueError('research_only')
    implementation = {str(p.relative_to(ROOT)): sha(p) for p in sorted((ROOT / 'evaluation/framework/scoring_calibration').glob('*.py'))}
    implementation[str(POLICY.relative_to(ROOT))] = sha(POLICY)
    save(OUT / 'experiment_specification.json', dict(implementation=implementation, policy=policy,
        config_hash=digest_map(policy), formulas=dict(
            A='S=clip(Q*M*T-C-D); Q=sum(group support)/(sum(observed support reliability)+w0*n_observed_zero)',
            B='S=clip((1-product(1-max_in_dependency_group(s*r))))*T-C-D; network/session/context collapsed',
            C='S=clip(max(min(M,weak_cap),max_anchor(r_anchor*(rarity_floor+(1-rarity_floor)*s))*(context_floor+(1-context_floor)*context))*T-C-D)'),
        independence='max within context(IP/HOST/URL/DOMAIN), execution(PROCESS/FILE/COMMAND), account and scoped session; B merges session/context; C anchor is alternative, never summed',
        reliability='Frozen source-independent feature reliability, except configured exact typed-anchor pathway; no source-type bonus',
        parent_only='Both occurrences exclusively parent_process => shared ancestor, not same child instance; downweight to parent_only_factor, no anchor',
        missing='MISSING excluded; UNOBSERVABLE excluded; observed zero affects A confidence only; contradiction and duplicate subtract frozen penalties',
        time='T=time_floor+(1-time_floor)*frozen_TimeScore; time never a positive independent clue',
        roles='Only existing scoped entity occurrence roles; no native event_id/raw_pointer/fixture identifier in arithmetic',
        typed_binding='Exact existing SESSION with typed scope, or full PROCESS host/pid/start_time and non-parent-only role, or frozen attested relation',
        bounds='clamp[0,1]; existing hard/duplicate guard and member validity retained; weak-only ceiling; no score floor',
        protocol='All three formulas and all five policies sealed before joining truth. Finite declared threshold grid. LOFO selects only on other groups. Final Dataset is development, not independent test.',
        selection='HN exposure first, then GT misses, policy simplicity, distance from .65, total edges; maximum total 1.25x baseline; GT>=5 and HN<=48',
        boundary='No candidate regeneration, adapter/projection/dataset changes, chain/incident construction, or production installation'))
    destination = OUT / 'predictions'
    destination.mkdir(exist_ok=False)
    started = time.perf_counter()
    models = policy['models']
    names = ['baseline'] + [m + ':' + p for m in models for p in policy['policies']]
    previous = None
    best = {}
    observed = None
    members = candidates = 0
    baseline_admitted = 0
    score_hash = hashlib.sha256()
    metamorphic = 0
    max_recompute_error = 0.
    from app.correlation.formula_v5 import aggregate_semantics
    with guard(paths, destination) as (events, reads):
        alerts = {r['alert_id']: r for r in rows(paths[0])}
        entities = {r['entity_id']: r for r in rows(paths[1])}
        expected = {tuple(p) for p in read(paths[3])}
        seen = set()
        with gzip.open(destination / 'member_features.jsonl.gz', 'wt', encoding='utf8', compresslevel=1) as features_out, \
             gzip.open(destination / 'members.jsonl.gz', 'wt', encoding='utf8', compresslevel=1) as members_out, \
             gzip.open(destination / 'candidates.jsonl.gz', 'wt', encoding='utf8', compresslevel=1) as pairs_out:
            def flush():
                nonlocal candidates, baseline_admitted
                if previous is None:
                    return
                candidates += 1
                baseline_admitted += bool(best.get('baseline') and best['baseline']['score'] >= .65)
                dump(pairs_out, dict(support_key=previous, results=best, observed_baseline=observed))
            with gzip.open(paths[2], 'rt', encoding='utf8') as stream:
                for line in stream:
                    if not line.startswith('{"stage":"member_score"'):
                        continue
                    row = json.loads(line)
                    pair = tuple(row['support_key'])
                    if pair != previous:
                        flush()
                        if pair in seen or pair not in expected:
                            raise ValueError('candidate_order_or_membership_invalid')
                        seen.add(pair)
                        previous, best, observed = pair, {}, None
                    members += 1
                    a, b = [alerts[i] for i in row['support_pair']]
                    tie = (a['timestamp'], b['timestamp'], a['alert_id'], b['alert_id'])
                    v5 = row['evidence']['evidence_v5']
                    frozen = aggregate_semantics(v5['features'], v5['policy'], hard=v5['gate']['hard_contradiction'],
                        duplicate_risk=v5['gate']['duplicate_observation'], duplicate=v5['duplicate'])
                    error = abs(frozen['final_score'] - row['score'])
                    max_recompute_error = max(max_recompute_error, error)
                    if error > 1e-12:
                        raise ValueError('frozen_formula_not_reproduced')
                    baseline = dict(score=row['score'], effective_score=row['score'], gate=row['valid'],
                                    support_pair=row['support_pair'], tie=tie, anchor=False,
                                    mass=v5['evidence_mass'], contradiction=v5['conflict_penalty'] > 0)
                    if observed is None or (-baseline['score'], tie) < (-observed['score'], observed['tie']):
                        observed = baseline
                    if row['valid'] and ('baseline' not in best or (-baseline['score'], tie) < (-best['baseline']['score'], best['baseline']['tie'])):
                        best['baseline'] = baseline
                    env, bindings = project(row, alerts, entities)
                    experimental = {m: score(env, policy, m) for m in models}
                    if members <= 64:
                        changed = {**env, 'features': list(reversed(env['features']))}
                        for m in models:
                            if score(changed, policy, m) != experimental[m]:
                                raise ValueError('order_metamorphic_failed')
                        metamorphic += 1
                    for m, result in experimental.items():
                        for p in policy['policies']:
                            if not result['gate'] or (p == 'strong_anchor' and not result['anchor']) or (
                                    p == 'contradiction_gate' and result['contradiction']) or (
                                    p == 'mass_floor' and result['mass'] < policy['mass_floor']):
                                continue
                            adjusted = result['score'] - (policy['context_threshold_increment']
                                if p == 'evidence_class' and not result['anchor'] else 0.)
                            name = m + ':' + p
                            value = dict(score=result['score'], effective_score=adjusted, gate=True, tie=tie,
                                support_pair=row['support_pair'], anchor=result['anchor'],
                                mass=result['mass'], contradiction=result['contradiction'])
                            if name not in best or (-adjusted, tie) < (-best[name]['effective_score'], best[name]['tie']):
                                best[name] = value
                    full = dict(support_key=pair, support_pair=row['support_pair'],
                        delta_t=abs(__import__('datetime').datetime.fromisoformat(a['timestamp'].replace('Z', '+00:00')).timestamp() -
                                    __import__('datetime').datetime.fromisoformat(b['timestamp'].replace('Z', '+00:00')).timestamp()),
                        source_a=a['raw_alert'].get('source_type', a['source_type']),
                        source_b=b['raw_alert'].get('source_type', b['source_type']),
                        shared_entities=sorted(set(a['entity_ids']) & set(b['entity_ids'])),
                        typed_bindings=bindings, observable_dimensions=v5['features'],
                        baseline=v5, values=row['values'], contributions=row['contributions'],
                        valid=row['valid'], rejection_codes=row['rejection_codes'])
                    dump(features_out, full)
                    dump(members_out, dict(support_key=pair, support_pair=row['support_pair'],
                         baseline=baseline, experiments=experimental))
                    hashed = {k: row[k] for k in ('support_key', 'support_pair', 'values', 'raw_total', 'score', 'valid', 'rejection_codes')}
                    score_hash.update(json.dumps(hashed, sort_keys=True, separators=(',', ':')).encode())
                    if members % 25000 == 0:
                        print('MEMBERS', members, 'CANDIDATES', candidates, 'SECONDS', round(time.perf_counter()-started), flush=True)
            flush()
        candidate_digest = hashlib.sha256(json.dumps(sorted(seen), separators=(',', ':')).encode()).hexdigest()
        if seen != expected or candidates != 240621 or members != 241464 or baseline_admitted != 14788:
            raise ValueError('baseline_counts_mismatch')
        if candidate_digest != seal['candidate_digest'] or score_hash.hexdigest() != seal['score_digest']:
            raise ValueError('baseline_digest_mismatch')
        save(destination / 'receipt.json', dict(candidates=candidates, members=members,
            baseline_admitted=baseline_admitted, candidate_digest=candidate_digest, score_digest=score_hash.hexdigest(),
            max_frozen_recompute_error=max_recompute_error, order_metamorphic_pairs=metamorphic,
            reads=sorted(reads), denied_events=events, truth_read=False, source_capabilities_read=False,
            seconds=time.perf_counter()-started, guard='trusted Python audit tripwire; not OS sandbox'))
    files = {p.relative_to(OUT).as_posix(): sha(p) for p in sorted(destination.glob('*'))}
    save(OUT / 'prediction_seal.json', dict(status='SEALED', files=files,
        specification_sha256=sha(OUT / 'experiment_specification.json'), implementation=implementation,
        ground_truth_loaded=False, candidate_policy_unchanged=True))
    print('PREDICTIONS_SEALED', members, candidates, baseline_admitted, flush=True)


if __name__ == '__main__':
    sys.path.insert(0, str(ROOT / 'backend'))
    run()
