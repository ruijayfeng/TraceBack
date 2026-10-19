"""Record immutable inputs and a prospective F3 rule before implementation."""
from . import ROOT, OUT
from evaluation.framework.formula_design.runtime import read, save, sha


def run():
    if (OUT/'before.json').exists():
        raise ValueError('already_prepared')
    old = read(ROOT/'outputs/v5_validation_threshold_calibration/preparation.json')
    protected = {k:v for k,v in old['protected_files'].items() if not k.startswith('backend/app/')}
    protected.update({p.relative_to(ROOT).as_posix():sha(p) for p in (ROOT/'configs').rglob('*.yaml')})
    protected.update({p.relative_to(ROOT).as_posix():sha(p) for p in (ROOT/'docs').glob('*.md')})
    protected['AGENTS.md'] = sha(ROOT/'AGENTS.md')
    protected['backend/app/correlation/candidates.py'] = sha(ROOT/'backend/app/correlation/candidates.py')
    protected['backend/app/correlation/evidence_v4.py'] = sha(ROOT/'backend/app/correlation/evidence_v4.py')
    save(OUT/'before.json', dict(protected_files=protected, dataset_files=old['dataset_files'],
        production_files={p.relative_to(ROOT).as_posix():sha(p) for p in (ROOT/'backend/app').rglob('*.py')},
        prior_F2_seal_sha256=sha(ROOT/'outputs/v5_validation_threshold_calibration/scored_seal.json'),
        planned_revision='F3-independent-support-v1', max_revisions=1,
        rationale=[dict(old='flat observed denominator',failure='unrelated alternative-path zeros dilute support',
            new='bounded union of reliable semantic groups; zeros remain auditable, explicit contradiction penalizes',
            general_effect='independent affirmative evidence can accumulate; missing fields never increase score',
            negative_risk='shared host/account can still over-correlate; hot context and duplicate protections required'),
            dict(old='hard contextual-role whitelist',failure='weak context rejected independently of score',
            new='hard only contradictions/duplicate/no semantic support; single weak group capped',
            general_effect='weak pairs may be scored/admissible only at explicitly low thresholds',
            negative_risk='low thresholds expose more weak background pairs'),
            dict(old='all evidence averaged despite direct relation',failure='strong propagation diluted by unrelated zero dimensions',
            new='direct attested relation is a sufficient alternative pathway, never consumes unrelated corroboration twice',
            general_effect='field-proven propagation reaches the 0.70 band when reliable',
            negative_risk='upstream false attestation remains a risk; relation verifier unchanged')],
        thresholds=dict(admission=.65,clustering=.70,chain=.70,direction=.75),
        selection='freeze formula -> blind seal -> evaluation -> threshold sweep -> downstream replay; no safe all-witness region means NONE',
        acceptance='improved PR/AP, less overlap; actual directed multistep chain, stable region, no giant/background collapse',
        no_candidate_change=True,t2_read=False))
    print('PROSPECTIVE_DESIGN_SAVED',flush=True)


if __name__ == '__main__':
    run()
