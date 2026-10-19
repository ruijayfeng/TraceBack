"""Required selected-candidate ablations; independently blind, then sealed.

This supplement changes neither selected formula nor parameters. The user required
the five removals for the final candidate; the initial run had applied them to F3.
Coverage/interactions are explicit structural no-ops for selected F2.
"""
from array import array
from bisect import bisect_left,bisect_right
import gzip
import json
import math
import sys

from . import ROOT,OUT,BASELINE
from .runtime import read,save,sha,rows,require_sealed,guard,ABLATIONS

DEST=OUT/'selected_ablation_blind'


def blind():
    # No sidecars, evaluation labels or chosen individual pairs enter this worker.
    main=require_sealed();policy=read(OUT/'preparation.json')['policy']
    from .model import Evidence,Envelope,score
    if (OUT/'selected_ablation_seal.json').exists():raise ValueError('immutable_ablation_seal')
    DEST.mkdir(exist_ok=False)
    source=OUT/'blind/predictions.jsonl.gz';count=0;max_error=0.
    with guard([source],DEST) as (events,reads):
        with gzip.open(DEST/'predictions.jsonl.gz','wt',encoding='utf8',compresslevel=1) as f:
            for row in rows(source):
                dims={d['dimension']:d for d in row['v4_dimensions']}
                ev=tuple(Evidence(e['name'],e['family'],e['state'],e['strength'],e['reliability'],
                    tuple(e['provenance']),e['role'],e['weight'],dims[e['name']]['strength'])
                    for k in ('supporting_evidence','weak_evidence','unavailable_evidence','observed_zero_evidence') for e in row['evidence'][k])
                f0=row['results']['F0'];env=Envelope(ev,tuple(row['evidence']['contradictions']),
                    f0['duplicate_penalty']/policy['duplicate_weight'],f0['gates']['duplicate_risk'],f0['gates']['old_gate'],
                    f0['final_score'],f0['positive_support'],f0['conflict_penalty']/policy['conflict_weight'],())
                baseline=score(env,policy,'F2')
                max_error=max(max_error,abs(baseline['final_score']-row['results']['F2']['final_score']))
                if max_error>1e-12:raise ValueError('evidence_envelope_not_faithful')
                results={'F2':baseline,**{a:score(env,policy,'F2',ablation=a) for a in ABLATIONS}}
                f.write(json.dumps(dict(support_pair=row['support_pair'],results={m:dict(final_score=v['final_score'],reference_admitted=v['reference_admitted']) for m,v in results.items()}),separators=(',',':'))+'\n')
                count+=1
                if count%50000==0:print('BLIND_F2_ABLATION',count,flush=True)
        save(DEST/'guard_receipt.json',dict(rejected_events=events,non_code_reads=sorted(reads),ground_truth_loaded=False))
    save(OUT/'selected_ablation_seal.json',dict(status='completed',ground_truth_loaded=False,threshold=.65,
        selected_candidate='F2',selection_changed=False,parameters_changed=False,member_count=count,
        original_f2_replay_max_error=max_error,parent_prediction_sha256=main['files']['blind/predictions.jsonl.gz'],
        implementation_sha256=sha(__file__),policy_sha256=sha(ROOT/'evaluation/configs/v5_formula_design.yaml'),
        inherited_formula_implementation=read(OUT/'preparation.json')['implementation'],
        limitations='Additional required ablations after first comparison, using fixed formula and user-requested removals; labels excluded from worker. No formula reselection.',
        files={p.relative_to(OUT).as_posix():sha(p) for p in DEST.iterdir() if p.is_file()}))


def evaluate():
    require_sealed();sealed=read(OUT/'selected_ablation_seal.json')
    if sealed['ground_truth_loaded'] or sealed['status']!='completed' or sealed['implementation_sha256']!=sha(__file__):raise ValueError('ablation_unsealed')
    for name,h in sealed['files'].items():
        if sha(OUT/name)!=h:raise ValueError('ablation_prediction_changed')
    from .evaluate import ordering,dist
    from evaluation.framework.v4_semisynthetic_baseline import truth
    aa={r['alert_id']:r for r in rows(BASELINE/'blind/canonical.jsonl.gz')}
    oldout,oldseal=truth.OUT,truth.require_sealed
    try:
        truth.OUT=OUT;truth.require_sealed=require_sealed;labels=truth.load(aa)
    finally:truth.OUT=oldout;truth.require_sealed=oldseal
    witnesses={e:next(iter(ws)) for e,ws in labels['witnesses'].items()};pair_names={p:e for e,p in witnesses.items()}
    vector={m:array('d') for m in ('F2',*ABLATIONS)};pop={p:[] for p in ('gt','explicit_negative','hard_touch','background')}
    pairs=[];details={m:{} for m in vector};admitted={m:0 for m in vector}
    for row in rows(DEST/'predictions.jsonl.gz'):
        pair=tuple(sorted(row['support_pair']));i=len(pairs);pairs.append(pair)
        if pair in pair_names:pop['gt'].append(i)
        if pair in labels['negative_pairs']:pop['explicit_negative'].append(i)
        if set(pair)&labels['hard_ids']:pop['hard_touch'].append(i)
        if set(pair)<=labels['background_ids']:pop['background'].append(i)
        for m,r in row['results'].items():
            vector[m].append(r['final_score']);admitted[m]+=r['reference_admitted']
            if pair in pair_names:details[m][pair_names[pair]]=r['final_score']
    idx={p:i for i,p in enumerate(pairs)};results={}
    for m,values in vector.items():
        ordered=sorted(values);n=len(values);ranks={}
        for e,p in witnesses.items():
            s=values[idx[p]];lo,hi=bisect_left(ordered,s),bisect_right(ordered,s)
            ranks[e]=dict(score=s,rank=n-hi+1+sum(values[j]==s and q<p for j,q in enumerate(pairs)),
                percentile=100*(lo+.5*(hi-lo))/n)
        results[m]=dict(distributions={p:dist(values[i] for i in indices) for p,indices in pop.items()},
            ranking=ranks,pairwise=ordering(details[m],[values[i] for i in pop['explicit_negative']]),
            reference_admitted_members=admitted[m],threshold=.65,
            effect='structural_noop_candidate_does_not_use_component' if m in {'remove_coverage_confidence','remove_interactions'} else 'single_component_removal')
    save(OUT/'selected_formula_ablation.json',dict(candidate='F2',results=results,seal_sha256=sha(OUT/'selected_ablation_seal.json'),
        final_candidate_changed=False,coverage_interactions='Absent from F2, so removal must reproduce F2 exactly; reported as no-op rather than a measured benefit.'))
    previous=read(OUT/'ablation.json')
    save(OUT/'ablation.json',dict(exploratory_F3=previous,selected_F2=results))
    if vector['F2']!=vector['remove_coverage_confidence'] or vector['F2']!=vector['remove_interactions']:raise ValueError('structural_noop_changed_scores')
    print({m:r['pairwise']['strict_rate'] for m,r in results.items()},flush=True)


if __name__=='__main__':{'blind':blind,'evaluate':evaluate}[sys.argv[1]]()
