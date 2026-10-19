"""Independent post-seal arithmetic/provenance audit. No scoring or fitting calls."""
import math
from collections import Counter

from . import OUT,BASELINE
from .runtime import read,save,rows,require_sealed,sha


def recompute_f2(row,policy):
    evidence=row['evidence']
    ds=[e for k in ('supporting_evidence','weak_evidence','observed_zero_evidence') for e in evidence[k]
        if e['family']!='time']
    den=math.fsum(e['weight']*e['reliability'] for e in ds)
    mass=math.fsum(e['weight']*e['reliability']*e['strength'] for e in ds)
    support=mass/den if den else 0.
    r=row['results']['F2'];g=r['gates']
    positive=support*(policy['time_floor']+(1-policy['time_floor'])*r['temporal_compatibility'])
    final=max(0.,min(1.,positive-r['conflict_penalty']-r['duplicate_penalty']))
    if g['weak_only']:final=min(final,policy['weak_ceiling'])
    if not g['non_temporal_semantics'] or g['hard'] or g['duplicate_risk']:final=0.
    return dict(final_score=final,support_score=support,positive_support=positive,
        denominator=den,matched_mass=mass,dimensions=[dict(name=e['name'],state=e['state'],
            strength=e['strength'],reliability=e['reliability'],dimension_weight=e['weight'],
            effective_mass=e['weight']*e['reliability'],matched_mass=e['weight']*e['reliability']*e['strength']) for e in ds])


def pointer(raw,pointer):
    if pointer=='':return raw
    if not pointer.startswith('/'):raise ValueError('invalid_pointer')
    for token in pointer[1:].split('/'):
        token=token.replace('~1','/').replace('~0','~')
        raw=raw[int(token)] if isinstance(raw,list) else raw[token]
    return raw


def run():
    seal=require_sealed();policy=read(OUT/'preparation.json')['policy']
    canonical={a['alert_id']:a for a in rows(BASELINE/'blind/canonical.jsonl.gz')}
    gt=read(OUT/'gt_comparison.json');contrast=read(OUT/'gte03_e05_vs_hardnegative.json')
    target={tuple(sorted(gt[e]['F2']['support_pair'])):e for e in ('GT-E03','GT-E05')}
    target[tuple(sorted(contrast['original_max_hard_negative']['F2']['support_pair']))]='original_max_hard_negative'
    target[tuple(sorted(contrast['per_formula_max_hard_negative']['F2']['support_pair']))]='f2_max_hard_negative'
    errors=[];max_error=0.;count=0;refs=0;weak=0;details={};states=Counter()
    for row in rows(OUT/'blind/predictions.jsonl.gz'):
        audit=recompute_f2(row,policy);result=row['results']['F2'];count+=1
        max_error=max(max_error,max(abs(audit[k]-result[k]) for k in ('final_score','support_score','positive_support')))
        if result['gates']['weak_only']:
            weak+=1
            if result['final_score']>policy['weak_ceiling']:errors.append('weak_inflation')
        pair=tuple(sorted(row['support_pair']))
        if pair in target:details[target[pair]]=dict(audit,recorded=result)
        for key in ('supporting_evidence','weak_evidence','observed_zero_evidence','unavailable_evidence'):
            for e in row['evidence'][key]:
                states[e['state']]+=1
                for ref in e['provenance']:
                    refs+=1
                    if ref['alert_id'] not in pair:raise ValueError('borrowed_member_provenance')
                    pointer(canonical[ref['alert_id']]['raw_alert'],ref['pointer'])
    if max_error>1e-12:errors.append('recomputation_mismatch')
    result=dict(status='FAIL' if errors else 'PASS',members=count,expected_members=seal['member_count'],
        max_absolute_error=max_error,weak_ceiling_checked_members=weak,bound_pointers_resolved=refs,
        evidence_state_counts=dict(states),errors=errors,no_score_runtime_calls=True,
        prediction_sha256=sha(OUT/'blind/predictions.jsonl.gz'))
    save(OUT/'formula_recompute_audit.json',result)
    save(OUT/'discrimination_case_audit.json',dict(cases=details,
        interpretation='The F2 negative still exceeds E03. E03 has observed-zero PROCESS (not a contradiction), which enters its available denominator; the hard pair has no observed process dimension. Both share actual role-compatible host/account context. E05 exceeds the original and current hard maximum, E03 does not. This remaining weakness is disclosed, not tuned away.'))
    # Same observed support, varying *unavailable* dimension count cannot alter
    # any formula. Distinguish the fixed mass ceiling from observed-zero dilution.
    w_available=.5;matched=.4;total=1.
    save(OUT/'missing_evidence_counterfactuals.json',dict(
        construction='analytical counterfactual; same T=.8 and entity=.8, weights .2/.3; no labels',
        sparse=dict(available_mass=w_available,matched_mass=matched,v4=.65*matched/w_available+.35*matched/total),
        rich_unavailable_only=dict(extra_unavailable_dimensions=20,v4=.65*matched/w_available+.35*matched/total),
        rich_observed_zero_relation=dict(available_mass=.86,v4=.65*matched/.86+.35*matched/total),
        available_only_quality=matched/w_available,
        conclusion='H1 is qualified: unavailable count alone creates no rich/sparse gap. Fixed mass retains .35 of all configured-family normalization; observed-zero availability separately lowers quality. Unobserved and observed-zero must not be conflated.',
        f3_same_weak_semantic_support=read(OUT/'synthetic_counterexamples.json')['F']))
    if errors or count!=seal['member_count']:raise ValueError('independent_audit_failed')
    print(result,flush=True)


if __name__=='__main__':run()
