"""Post-seal semantic review and sensitivity; never defines new ground truth."""
from copy import deepcopy
import collections
import hashlib
import json
from . import BASE, OUT
from .snapshot import read, save
from .replay import rows
from .model import project, score
from .evaluate import pairkey, sample_push


def classify(a, b):
    shared = set(a['entity_ids']) & set(b['entity_ids'])
    def both(role, entity):
        return all(any(o['entity_id'] == entity and o['role'] == role for o in x['entity_occurrences']) for x in (a, b))
    session = any(both('session', e) for e in shared)
    process = any(both('process', e) for e in shared)
    ancestor = any(both('parent_process', e) for e in shared)
    equal_category = a['category'] == b['category']
    if process and equal_category:
        category = 'duplicate/repeated observation'
        reason = 'Exact primary process instance and same mapped category; repeated observations can be legitimate.'
    elif session and equal_category:
        category = 'likely legitimate operational correlation'
        reason = 'Exact scoped session and same mapped category; session continuity is observable, maliciousness is unknown.'
    elif session or process:
        category = 'suspicious progression-compatible'
        reason = 'Specific session/primary process identity spans different observed categories; compatibility is not proof of attack progression.'
    elif ancestor:
        category = 'likely over-correlation'
        reason = 'Shared ancestor without shared primary process or session; independent child observations can share infrastructure.'
    elif any(both('host', e) for e in shared):
        category = 'shared infrastructure'
        reason = 'Common host context without specific session/primary-instance identity.'
    elif shared:
        category = 'weak ambiguous relation'
        reason = 'Shared context without a specific instance/session binding.'
    else:
        category = 'unknown'
        reason = 'No shared canonical identity supports this semantic classification.'
    return dict(category=category, explanation=reason, shared_session=session,
                shared_primary_process=process, shared_parent_process=ancestor,
                same_mapped_category=equal_category, provisional=True,
                not_ground_truth=True, no_maliciousness_or_false_positive_label=True)


def enrich(d):
    if d is None:
        return None
    baseline = d['baseline']
    # Deterministic telescoping mass allocation to groups; explicit alternative
    # direct proof receives the positive mass only when that pathway dominates.
    remaining = 1.
    allocations = {}
    for group, value in sorted(baseline['group_support'].items()):
        allocations[group] = remaining * value * baseline['temporal_factor']
        remaining *= 1-value
    direct_wins = baseline['direct_support'] >= baseline['evidence_mass']*baseline['temporal_factor']
    candidates = collections.defaultdict(list)
    for f in d['observable_dimensions']:
        if f['state'] != 'OBSERVED_SUPPORT' or f['family'] not in {'entity', 'relation'} or f['role'] == 'direct':
            continue
        kind = f['name'].removeprefix('entity.')
        group = ('asset' if kind in {'IP', 'HOST'} or f['role'] in {'endpoint', 'flow', 'host'} else
                 'resource' if kind in {'URL', 'DOMAIN'} else
                 'execution' if kind in {'PROCESS', 'FILE', 'COMMAND'} else f['name'])
        candidates[group].append(f)
    credits = {}
    for group, fs in candidates.items():
        winner = min(fs, key=lambda f: (-f['strength']*f['reliability'], f['name']))
        credits[winner['name']] = 0. if direct_wins else allocations.get(group, 0.)
    if direct_wins:
        direct = [f for f in d['observable_dimensions'] if f['state'] == 'OBSERVED_SUPPORT' and f['role'] == 'direct']
        if direct:
            winner = min(direct, key=lambda f: (-f['strength']*f['reliability'], f['name']))
            credits[winner['name']] = baseline['direct_support']
    audited = []
    state_names = dict(OBSERVED_SUPPORT='SUPPORTED', OBSERVED_NEUTRAL='OBSERVED_ZERO / NO_SUPPORT',
                       OBSERVED_CONTRADICTION='CONTRADICTORY', MISSING='MISSING', UNOBSERVABLE='UNOBSERVABLE')
    conflicts = [f for f in d['observable_dimensions'] if f['state'] == 'OBSERVED_CONTRADICTION']
    conflict_winner = min(conflicts, key=lambda f: (-f['reliability'], f['name']))['name'] if conflicts else None
    for f in d['observable_dimensions']:
        audited.append(dict(feature_family=f['family'], feature=f['name'],
            raw_support=f['strength'], normalized_support=f['strength']*f['reliability'] if f['state'] == 'OBSERVED_SUPPORT' else 0.,
            quality_reliability=f['reliability'], positive_contribution=credits.get(f['name'], 0.),
            negative_contribution=-baseline['conflict_penalty'] if f['name'] == conflict_winner else 0.,
            state=state_names[f['state']], conflict_state=f['state'] == 'OBSERVED_CONTRADICTION',
            hot=f['hot'], provenance=f['provenance'], entity_ids=f['entity_ids']))
    return dict(**d, feature_contributions=audited,
        attribution='Baseline positive mass: sorted-group telescoping allocation to maximal supporting feature; not a statistical independence claim. Time is a multiplier, metadata/source have zero independent credit. Ceilings/gates apply after allocation.',
        duplicate_negative_contribution=-baseline['duplicate_penalty'],
        pre_ceiling_score=max(0., min(1., baseline['raw_total'])), post_ceiling_score=baseline['final_score'],
        final_score=baseline['final_score'], gate_result=baseline['gate'],
        admission_result=d['valid'] and baseline['final_score'] >= .65)


def run():
    policy = read(OUT / 'experiment_specification.json')['policy']
    summary = read(OUT / 'evaluation_summary.json')
    selected = summary['selected']
    if selected is None:
        raise ValueError('no_candidate_selected')
    alerts = {r['alert_id']: r for r in rows(BASE / 'blind_A/canonical.jsonl.gz')}
    entities = {r['entity_id']: r for r in rows(BASE / 'blind_A/entities.jsonl.gz')}
    witnesses = read(OUT / 'witness_decomposition.json')
    samples = read(OUT / 'sample_decomposition.json')
    for w in witnesses:
        w['features'] = enrich(w['features'])
    for values in samples.values():
        for v in values:
            v['features'] = enrich(v['features'])
    save(OUT / 'complete_witness_decomposition.json', witnesses)
    save(OUT / 'complete_sample_decomposition.json', samples)
    reviews = []
    for stratum in ('high', 'near', 'random'):
        for v in samples[stratum]:
            aa, bb = v['selection']['support_pair']
            reviews.append(dict(stratum=stratum, support_pair=[aa, bb],
                baseline_score=v['selection']['score'], **classify(alerts[aa], alerts[bb])))
    save(OUT / 'background_semantic_review.json', dict(rows=reviews,
        counts={s: dict(collections.Counter(r['category'] for r in reviews if r['stratum'] == s))
                for s in ('high', 'near', 'random')},
        method='Deterministic source-field semantic triage, provisional and reviewable. Not an independently adjudicated set, not new labels or a precision estimate. Random sample excludes high/near selected IDs.',
        sample_size=300, unique_pairs=len({tuple(r['support_pair']) for r in reviews}),
        sampling='High100 and near100 can overlap; random100 uses seeded hash ranking and excludes both.'))
    negative_samples = [r for r in witnesses if r['scenario_id'] and r['baseline_score'] is not None]
    save(OUT / 'hard_negative_extreme_samples.json', dict(
        highest_rejected=sorted([r for r in negative_samples if not r['baseline_admitted']],
                                key=lambda r: (-r['baseline_score'], r['original_pair']))[:25],
        lowest_admitted=sorted([r for r in negative_samples if r['baseline_admitted']],
                               key=lambda r: (r['baseline_score'], r['original_pair']))[:25]))
    # One-factor sensitivity of observed witness evidence. No parameter search/refit.
    sensitivity = []
    for parameter in ('anchor_reliability', 'anchor_rarity_floor', 'minimum_anchor_strength', 'parent_only_factor', 'time_floor'):
        for factor in policy['sensitivity_multipliers']:
            cfg = deepcopy(policy)
            cfg[parameter] = min(1., policy[parameter]*factor)
            positives, negatives = [], []
            for w in witnesses:
                if w['features'] is None:
                    continue
                d = w['features']
                row = dict(support_pair=d['support_pair'], valid=d['valid'],
                           evidence=dict(evidence_v5=d['baseline']))
                env, _ = project(row, alerts, entities)
                result = score(env, cfg, selected['model'])
                (negatives if w['scenario_id'] else positives).append(result['score'])
            sensitivity.append(dict(parameter=parameter, multiplier=factor, value=cfg[parameter],
                gt_admitted=sum(v >= selected['threshold'] for v in positives),
                hn_admitted=sum(v >= selected['threshold'] for v in negatives),
                hn_rejection_rate=1-sum(v >= selected['threshold'] for v in negatives)/180,
                margin=min(positives)-max(negatives), minimum_gt_score=min(positives)))
    save(OUT / 'parameter_sensitivity.json', dict(rows=sensitivity,
         scope='Exact 7 GT/168 scored HN members only; 12 un-nominated HN remain rejected. Not a full population replay; no retuning after this check.'))
    # New/removal audit for all representative pairs; selected-support identities
    # may differ from baseline and are deliberately not inferred from rep IDs.
    attack = {a for r in witnesses if not r['scenario_id'] for a in r['original_pair']}
    truth_data = __import__('pathlib').Path(read(BASE / 'preparation.json')['input']).parents[1]
    truth = read(truth_data / 'ground_truth/ground_truth.json')
    trace = {r['event_id']: r['alert_id'] for r in read(BASE / 'trace_map.json')}
    attack = {trace[o['alert_id']] for o in truth['observations']}
    negative_ids = {a for r in witnesses if r['scenario_id'] for a in r['original_pair']}
    background = set(alerts)-attack-negative_ids
    changes = collections.Counter()
    added_categories = collections.Counter()
    added_examples = []
    new_samples = {s: [] for s in ('high', 'near', 'random')}
    for row in rows(OUT / 'predictions/candidates.jsonl.gz'):
        b = row['results'].get('baseline')
        n = row['results'].get(selected['variant'])
        old = bool(b and b['effective_score'] >= .65)
        new = bool(n and n['effective_score'] >= selected['threshold'])
        changes['retained' if old and new else 'removed' if old else 'added' if new else 'both_rejected'] += 1
        if new:
            x, y = n['support_pair']
            if x in background and y in background:
                sample_push(new_samples['high'], n['score'], n)
                sample_push(new_samples['near'], -abs(n['score']-selected['threshold']), n)
                rank = int(hashlib.sha256((str(policy['sample_seed'])+'|'.join(row['support_key'])).encode()).hexdigest(), 16)
                sample_push(new_samples['random'], rank, n)
                if not old:
                    review = classify(alerts[x], alerts[y])
                    added_categories[review['category']] += 1
                    if len(added_examples) < 50:
                        added_examples.append(dict(support_key=row['support_key'], support_pair=[x, y], score=n['score'], **review))
                    changes['added_background_background'] += 1
        if old and not new:
            x, y = b['support_pair']
            if x in background and y in background:
                changes['removed_background_background'] += 1
    new_reviews = {s: [dict(selection=v[2], **classify(*[alerts[i] for i in v[2]['support_pair']]))
                       for v in sorted(values, reverse=True)] for s, values in new_samples.items()}
    save(OUT / 'admission_changes.json', dict(counts=changes, added_background_categories=added_categories,
        added_background_examples=added_examples, recommended_background_samples=new_reviews,
        limitation='Semantic compatibility of background is observable; false positive/attack status remains unlabelled. A shared exact benign session can still pass the recommended scorer.'))
    families = {}
    for family in sorted({w['scenario_id'] for w in witnesses if w['scenario_id']}):
        ww = [w for w in witnesses if w['scenario_id'] == family]
        examples = [w['features'] for w in ww if w['features']]
        parent_only = sum(any(f['feature'] == 'entity.PROCESS' and
            any(p['pointer'].endswith('parent_process_id') for p in f['provenance'])
            for f in d['feature_contributions']) for d in examples)
        families[family] = dict(count=len(ww), scored=len(examples), baseline_admitted=sum(w['baseline_admitted'] for w in ww),
            recommended_admitted=sum(bool(w['member_predictions'] and
                w['member_predictions']['experiments'][selected['model']]['score'] >= selected['threshold']) for w in ww),
            parent_only_feature_pairs=parent_only,
            dominant_false_support_features=['shared parent PROCESS instance', 'common HOST', 'same ACCOUNT', 'same COMMAND'] if parent_only else
                sorted({f['feature'] for d in examples for f in d['feature_contributions'] if f['positive_contribution'] > 0}),
            missing_disambiguating_features=['no shared primary child instance', 'no exact shared operation/session binding'] if parent_only else
                ['Pair-specific support preserved; see all 12 decompositions. Different sessions alone are NO_SUPPORT, not an exclusive contradiction.'],
            whether_current_formula_double_counts='Parent/context/account are not proven independent; parent alias got strong-identity treatment.' if parent_only else
                'Existing max per family prevents simple field duplication; remaining family dependence possible.',
            whether_gate_should_handle='Strong process anchor must reject parent-parent-only evidence; do not hard-reject legitimate sibling operational relations.' if parent_only else 'Existing guard retained.',
            whether_score_should_handle='Yes: role-aware parent factor and independent family handling.' if parent_only else 'Conservative grouping and existing penalties.',
            whether_admission_policy_should_handle='Global threshold suffices for this development comparison; no scenario-based rule.')
    save(OUT / 'hard_negative_family_diagnosis.json', families)
    print('AUDIT_COMPLETE', len(reviews), dict(changes), flush=True)


if __name__ == '__main__':
    run()
