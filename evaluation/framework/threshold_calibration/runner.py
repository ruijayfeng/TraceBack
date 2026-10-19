"""Verify immutable scores, seal a lossless F2 projection, then load labels.

No candidate generation, feature extraction or scoring runs in this module.
The immutable parent was produced in a label-denied worker before evaluation.
"""
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
import csv
import gzip
import hashlib
import json
import math
from pathlib import Path
import sys
import time

from . import ROOT, OUT
from .metrics import distribution, ranking_metrics, longest_path, classification, pareto, choose
from evaluation.framework.formula_design import OUT as PARENT, BASELINE, POLICY
from evaluation.framework.formula_design.runtime import read, save, sha, rows, require_sealed, guard


def verify_files(files, root=ROOT):
    for name, digest in files.items():
        if sha(root/name) != digest:
            raise ValueError('protected_file_changed:'+name)


def prepare():
    if (OUT/'preparation.json').exists():
        raise ValueError('immutable_calibration_preparation_exists')
    parent = require_sealed()
    selection = read(PARENT/'formula_selection.json')
    if not selection['V5_FORMULA_CANDIDATE_SELECTED'] or selection['selected_formula'] != 'F2':
        raise ValueError('no_frozen_executable_selected_F2')
    p = read(PARENT/'preparation.json')
    # Do not traverse/hash t2 or any other future external validation inputs.
    verify_files(p['protected_files'])
    verify_files(p['production_inventory'])
    from evaluation.framework.preformula_baseline.boundary import verify_current
    receipt = verify_current()
    dataset_root = Path(r'D:\Code_WorkSpace\TraceBack-Dataset')
    dataset = {k:v for k,v in p['dataset_inventory'].items()
               if k.startswith('data/traceback_semisynthetic_v1/')}
    verify_files(dataset, dataset_root)
    if not dataset:
        raise ValueError('no_frozen_calibration_dataset')
    implementation = {x.relative_to(ROOT).as_posix():sha(x) for x in Path(__file__).parent.glob('*.py')}
    protected = dict(p['protected_files'])
    protected.update(p['production_inventory'])
    protected.update({x.relative_to(ROOT).as_posix():sha(x) for x in PARENT.rglob('*')
                     if x.is_file() and '__pycache__' not in x.parts
                     and not any(part in x.parts for part in ('pytest_tmp','regression_isolated'))})
    policy = read(PARENT/'preparation.json')['policy']
    save(OUT/'preparation.json', dict(
        algorithm_version=policy['version']+'-f2',
        implementation_version='evaluation-only:F2; production=v5-preformula-candidate-v1',
        config_hash_before=hashlib.sha256(json.dumps(policy,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        config_hash_definition='SHA256 canonical JSON of frozen experimental policy (not YAML file bytes)',
        policy_sha256=sha(POLICY), parent_production_config_hash=receipt['config_hash'],
        mapping_digest=receipt['mapping_digest'], threshold_before=.65,
        dataset_hash=receipt['dataset_identity']['input_sha256'],
        ground_truth_hash=dataset['data/traceback_semisynthetic_v1/attack_scenarios/ground_truth.json'],
        dataset_files=dataset, protected_files=protected, implementation=implementation,
        git_commit=None, working_tree_status='unavailable:not_a_git_repository',
        parent_seal_sha256=sha(PARENT/'blind_manifest.json'), parent_seal=parent,
        formula_selection_sha256=sha(PARENT/'formula_selection.json'),
        scoring_rerun=False, threshold_only=True, t2_read=False,
        selection_rule='maximize GT recovery then GT correlation-path proxy; minimize labeled FP, unlabeled volume, total volume; highest threshold',
        production_freeze_rule='requires actual chain recovery, no unresolved integration blocker, and stable operating point; otherwise NONE',
        metric_policy='annotated-only primary; unannotated excluded. Closed-world operational proxy separately named.',
        grid='0.30..0.90 step0.01 plus exact unique-score and nextafter boundaries and endpoints',
        downstream_thresholds_unchanged=dict(clustering=.70,chain=.70)))
    print('PREPARED: immutable F2 implementation and scores verified', flush=True)


def extract():
    """Project existing scored results before this experiment reads any labels."""
    if (OUT/'scored_seal.json').exists() or (OUT/'evaluation_started.json').exists():
        raise ValueError('single_use_score_projection')
    p = read(OUT/'preparation.json')
    require_sealed()
    if sha(PARENT/'blind_manifest.json') != p['parent_seal_sha256']:
        raise ValueError('parent_seal_changed')
    destination = OUT/'scored'
    destination.mkdir(exist_ok=False)
    canonical = BASELINE/'blind/canonical.jsonl.gz'
    predictions = PARENT/'blind/predictions.jsonl.gz'
    start = time.perf_counter()
    candidates, seen = {}, set()
    with guard([canonical, predictions], destination) as (events, reads):
        alerts = {a['alert_id']:a for a in rows(canonical)}
        with gzip.open(destination/'members.jsonl.gz','wt',encoding='utf8',compresslevel=1) as f:
            for i, row in enumerate(rows(predictions), 1):
                result = row['results']['F2']
                pair, key = tuple(row['support_pair']), tuple(row['support_key'])
                if pair in seen:
                    raise ValueError('duplicate_member_pair')
                seen.add(pair)
                compact = dict(support_pair=pair,support_key=key,score=result['final_score'],
                               gate_passed=result['gates']['passed'],gates=result['gates'])
                f.write(json.dumps(compact,separators=(',',':'))+'\n')
                tie = (-compact['score'],alerts[pair[0]]['timestamp'],alerts[pair[1]]['timestamp'],*pair)
                item = candidates.setdefault(key, dict(count=0,best=None,best_valid=None))
                item['count'] += 1
                for name, permitted in (('best',True),('best_valid',compact['gate_passed'])):
                    if permitted and (item[name] is None or tie < item[name][0]):
                        item[name] = (tie,compact)
                if i%50000 == 0:
                    print('projected_members',i,flush=True)
        with gzip.open(destination/'candidates.jsonl.gz','wt',encoding='utf8',compresslevel=1) as f:
            for key,item in sorted(candidates.items()):
                selected = item['best_valid']
                row = dict(support_key=key,member_count=item['count'],
                           best_score=item['best'][1]['score'],
                           selected=selected[1] if selected else None)
                f.write(json.dumps(row,separators=(',',':'))+'\n')
        save(destination/'guard_receipt.json',dict(rejected_events=events,non_code_reads=sorted(reads),
              ground_truth_loaded=False,scoring_called=False,guard_type='Python audit hook; not OS sandbox'))
    if len(seen)!=p['parent_seal']['member_count'] or len(candidates)!=p['parent_seal']['candidate_count']:
        raise ValueError('incomplete_score_projection')
    save(OUT/'scored_seal.json',dict(status='completed',ground_truth_loaded=False,scoring_called=False,
        parent_seal_sha256=p['parent_seal_sha256'],member_count=len(seen),candidate_count=len(candidates),
        files={x.relative_to(OUT).as_posix():sha(x) for x in destination.iterdir()},
        seconds=time.perf_counter()-start))
    print('SCORED_PROJECTION_SEALED',len(seen),len(candidates),flush=True)


def verify_score_seal():
    seal = read(OUT/'scored_seal.json')
    if seal['status']!='completed' or seal['ground_truth_loaded'] or seal['scoring_called']:
        raise ValueError('unsealed_scores')
    verify_files(seal['files'],OUT)
    require_sealed()
    if sha(PARENT/'blind_manifest.json')!=seal['parent_seal_sha256']:
        raise ValueError('parent_changed')
    return dict(seal, raw_alert_count=read(OUT/'preparation.json')['parent_seal']['raw_alert_count'])


def load_labels(alerts):
    # This function cannot read GT until both original and projected scores verify.
    verify_score_seal()
    save(OUT/'evaluation_started.json',dict(scored_seal_sha256=sha(OUT/'scored_seal.json'),
        blind_manifest_sha256=sha(PARENT/'blind_manifest.json'),
        order='original blind scores sealed -> lossless F2 projection sealed -> GT -> calibration',
        scoring_after_truth=False))
    from evaluation.framework.v4_semisynthetic_baseline import truth
    # The accepted loader expects its historical manifest filename and locator.
    # These byte-identical references do not execute or overwrite the parent run.
    (OUT/'blind').mkdir(exist_ok=True)
    for source,target in ((PARENT/'blind_manifest.json',OUT/'blind_run_manifest.json'),
                          (PARENT/'blind/input_line_map.json',OUT/'blind/input_line_map.json')):
        if not target.exists():
            target.write_bytes(source.read_bytes())
        if sha(source)!=sha(target):
            raise ValueError('truth_loader_alias_changed')
    old_out, old_seal = truth.OUT,truth.require_sealed
    try:
        truth.OUT,truth.require_sealed = OUT,verify_score_seal
        return truth.load(alerts)
    finally:
        truth.OUT,truth.require_sealed = old_out,old_seal


def evaluate():
    if (OUT/'summary.json').exists():
        raise ValueError('calibration_already_delivered')
    seal = verify_score_seal()
    alerts = {a['alert_id']:a for a in rows(BASELINE/'blind/canonical.jsonl.gz')}
    labels = load_labels(alerts)
    witnesses = {e:next(iter(pairs)) for e,pairs in labels['witnesses'].items()}
    by_pair = {tuple(sorted(pair)):e for e,pair in witnesses.items()}
    negative, hard = labels['negative_pairs'],labels['hard_ids']
    owner = read(BASELINE/'blind/owner.json')
    gt_keys = {e:tuple(sorted(owner[a] for a in pair)) for e,pair in witnesses.items()}
    if len(set(gt_keys.values())) != 6:
        raise ValueError('GT_candidate_identity_collision')
    populations = defaultdict(list)
    annotated_positive, annotated_negative, all_negative = [],[],[]
    gt_rows, member_values, members = {},[],{}
    hard_values = []
    for row in rows(OUT/'scored/members.jsonl.gz'):
        pair = tuple(sorted(row['support_pair']))
        value = row['score']
        member_values.append(value)
        population = ('GT_TRUE_EDGE' if pair in by_pair else 'HARD_NEGATIVE' if set(pair)&hard
                      else 'OTHER_BACKGROUND_CANDIDATE')
        populations[population].append(value)
        if pair in by_pair:
            gt_rows[by_pair[pair]] = dict(row)
            annotated_positive.append(value)
        else:
            all_negative.append(value)
        if pair in negative:
            annotated_negative.append(value)
        if set(pair)&hard:
            hard_values.append(value)
        if pair in negative or pair in by_pair:
            members[pair] = row
    candidates = list(rows(OUT/'scored/candidates.jsonl.gz'))
    selected = [r['selected'] for r in candidates if r['selected'] is not None]
    selected.sort(key=lambda r:(r['score'],r['support_key']))
    selected_scores = [r['score'] for r in selected]
    candidate_map = {tuple(r['support_key']):r for r in candidates}
    all_scores = sorted(member_values)
    for e,row in gt_rows.items():
        score = row['score']
        lo, hi = bisect_left(all_scores,score),bisect_right(all_scores,score)
        row.update(edge_id=e,candidate_generated=gt_keys[e] in candidate_map,score_available=True,
                   score_rank_min=len(all_scores)-hi+1,score_rank_max=len(all_scores)-lo,
                   percentile=100*(lo+.5*(hi-lo))/len(all_scores),
                   candidate_score=candidate_map[gt_keys[e]]['best_score'],
                   selected_member_pair=candidate_map[gt_keys[e]]['selected'])
    if len(gt_rows)!=6:
        raise ValueError('missing_scored_GT_witness')
    # Candidate generation reasons come exclusively from the original diagnostics.
    targets=set(gt_keys.values())
    candidate_evidence={}
    digest=hashlib.sha256()
    for row in rows(BASELINE/'blind/diagnostics.jsonl.gz'):
        if row['stage']=='candidate':
            digest.update(json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n')
            key=tuple(row['support_key'])
            if key in targets:
                candidate_evidence[key]=row
    if digest.hexdigest()!=read(OUT/'preparation.json')['parent_seal']['candidate_digest']:
        raise ValueError('candidate_digest_changed')
    gt_def={e['edge_id']:e for e in labels['gt']['edges']}
    for e,row in gt_rows.items():
        edge=gt_def[e]
        row.update(source= edge['from'],target=edge['to'],
            attack_stage_from=labels['nodes'][edge['from']]['stage'],
            attack_stage_to=labels['nodes'][edge['to']]['stage'],
            candidate_generation_reason=candidate_evidence.get(gt_keys[e]),
            status='SCORED' if row['candidate_generated'] else 'BROKEN_AT_CANDIDATE')
    for row in rows(PARENT/'blind/predictions.jsonl.gz'):
        pair=tuple(sorted(row['support_pair']))
        if pair in by_pair:
            from evaluation.framework.formula_design.evaluate import explain
            detail=explain(row,'F2',read(PARENT/'preparation.json')['policy'])
            gt_rows[by_pair[pair]].update(main_positive_evidence=detail['supporting_evidence'],
                main_negative_evidence=detail['observed_zero_evidence']+detail['contradictions'],
                score_breakdown=detail)
    save(OUT/'ground_truth_edge_scores.json',dict(GT_EDGES_TOTAL=6,
        GT_EDGES_IN_CANDIDATES=len(candidate_evidence),CANDIDATE_RECALL=len(candidate_evidence)/6,
        gate_ceiling=sum(r['gate_passed'] for r in gt_rows.values()),edges=gt_rows))
    # Freeze scalar threshold grids from actual score boundaries; never rescore.
    thresholds={0.,1.,.65,*[i/100 for i in range(30,91)]}
    for value in set(selected_scores):
        thresholds.add(value)
        thresholds.add(math.nextafter(value,math.inf))
    # Primary exact-witness metrics: negatives are only the declared not_related pairs.
    def measure(t):
        admitted_witnesses={e for e,r in gt_rows.items() if r['gate_passed'] and r['score']>=t}
        fp=sum(r['gate_passed'] and r['score']>=t for pair,r in members.items() if pair in negative)
        # Representative graph volumes are deduplicated and never equal member counts.
        volume=len(selected_scores)-bisect_left(selected_scores,t)
        selected_labelled=sum(r['score']>=t and tuple(sorted(r['support_pair'])) in members for r in selected)
        exact_tp_selected=sum(r['score']>=t and tuple(sorted(r['support_pair'])) in by_pair for r in selected)
        path=longest_path([(gt_def[e]['from'],gt_def[e]['to']) for e in admitted_witnesses])
        return dict(threshold=t,total_admitted_edges=volume,**classification(len(admitted_witnesses),fp),
            GT_edge_recall=len(admitted_witnesses)/6,
            correlation_GT_longest_path_proxy=path,longest_GT_path_recovered=0,
            chain_completeness=0.,GT_correlation_witnesses_selected=exact_tp_selected,
            unlabeled_admitted=volume-selected_labelled,
            closed_world_proxy_FP=volume-exact_tp_selected,
            closed_world_proxy_precision=exact_tp_selected/volume if volume else None,
            primary_scope='exact annotated original witness pairs; not candidate representative counts',
            formal_V5_edges_published=False)
    metrics=[measure(t) for t in sorted(thresholds) if 0<=t<=1]
    best=choose(metrics)
    best_f1=max(metrics,key=lambda r: (r['F1'] or 0,-r['unlabeled_admitted'],r['threshold']))
    best_chain=max(metrics,key=lambda r:(r['chain_completeness'],r['threshold']))
    historical=measure(.65)
    representatives=dict(historical=historical,highest_threshold_maximum_GT_recall=best,
        best_F1=best_f1,best_chain_completeness=best_chain,recommended=None)
    with (OUT/'threshold_metrics.csv').open('w',encoding='utf8',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(metrics[0]))
        writer.writeheader();writer.writerows(metrics)
    # Avoid O(unique_scores^2) scans: primary metric states repeat between boundaries.
    states={}
    for row in metrics:
        key=(row['precision'],row['recall'],row['chain_completeness'],row['FP'])
        old=states.get(key)
        if old is None or row['threshold']>old['threshold']:
            states[key]=row
    save(OUT/'threshold_pareto.json',dict(primary_annotated_frontier=pareto(list(states.values())),
         representatives=representatives,omitted_equivalent_boundary_points='keep highest threshold per identical metric tuple'))
    stability=[measure(max(0,min(1,best['threshold']+delta))) for delta in (-.05,-.02,-.01,0,.01,.02,.05)]
    baseline_volume=best['total_admitted_edges']
    unstable=any(r['GT_TP']!=best['GT_TP'] or abs(r['total_admitted_edges']-baseline_volume)>max(10,.1*baseline_volume)
                 for r in stability if abs(r['threshold']-best['threshold'])<=.02000001)
    save(OUT/'threshold_stability.json',dict(recommended_threshold=None,
        diagnostic_point=best['threshold'],status='THRESHOLD_UNSTABLE' if unstable else 'STABLE_PLATEAU',
        definition='at +/-0.02 any GT loss or volume change >max(10,10%)',
        rows=stability,production_recommendation=False))
    distributions={k:distribution(v) for k,v in populations.items()}
    distributions.update(EXPLICIT_ANNOTATED_NEGATIVE=distribution(annotated_negative))
    save(OUT/'score_distribution.json',dict(population='all computed original member pairs, including gate rejects',
        definitions=dict(HARD_NEGATIVE='at least one of the 30 hard-negative alerts',
        OTHER_BACKGROUND_CANDIDATE='remaining non-GT, non-hard-touching members; includes unlabelled attack/background pairs'),
        distributions=distributions))
    separation=dict(annotated_only=ranking_metrics(annotated_positive,annotated_negative),
        closed_world_proxy=ranking_metrics(annotated_positive,all_negative),
        lowest_GT_score=min(annotated_positive),highest_negative_score=max(annotated_negative),
        highest_hard_touching_score=max(hard_values),score_margin=min(annotated_positive)-max(annotated_negative),
        evaluation_coverage=(len(annotated_positive)+len(annotated_negative))/len(member_values),
        explicit_negative_candidate_coverage=len(annotated_negative)/len(negative),
        status='POOR_SEPARATION',reason='E01 ranks in background body; gate rejects E01; negatives overlap other GT edges',
        unscored_negatives_excluded=True,unlabelled_background_excluded_from_primary_metrics=True)
    save(OUT/'scored_pairs_summary.json',dict(member_count=len(member_values),candidate_count=len(candidates),
        valid_candidate_count=len(selected),max_member_score=max(member_values),max_selected_score=max(selected_scores),
        scores_reused=True,source_sha256=sha(PARENT/'blind/predictions.jsonl.gz'),
        rank_scope='all original member pairs, tie ranks and midrank percentile',separation=separation))
    hard_members=[r for r in rows(OUT/'scored/members.jsonl.gz') if set(r['support_pair'])&hard]
    hard_candidates=[r for r in selected if set(r['support_pair'])&hard]
    save(OUT/'hard_negative_validation.json',dict(hard_negative_alerts=len(hard),
        hard_negative_candidate_pairs=len({tuple(r['support_key']) for r in hard_members}),
        hard_negative_member_pairs=len(hard_members),hard_negative_max_score=max(hard_values),
        hard_negative_p95_score=distribution(hard_values)['p95'],
        hard_negative_admitted_at_065=sum(r['score']>=.65 for r in hard_candidates),
        hard_negative_admitted_at_recommended_threshold=None,
        hard_negative_admitted_at_diagnostic_threshold=sum(r['score']>=best['threshold'] for r in hard_candidates),
        diagnostic_threshold=best['threshold'],recommended_threshold=None))
    save(OUT/'summary.json',dict(TASK_RESULT='V5_THRESHOLD_NO_SAFE_OPERATING_POINT',
        V5_VALIDATION='FAIL',V5_THRESHOLD_CALIBRATION='NO_SAFE_OPERATING_POINT',
        V5_FORMULA_FREEZE='NO_NEW_FREEZE_EXISTING_EXPERIMENT_RETAINED',V5_THRESHOLD_FREEZE='NO',
        READY_FOR_EXTERNAL_VALIDATION='NO',RECOMMENDED_THRESHOLD=None,
        candidate_recall=len(candidate_evidence)/6,score_separation=separation,
        historical=historical,representatives=representatives,
        blockers=['GT-E01 rejected by immutable evidence gate even at threshold zero',
                  'all F2 scores below fixed clustering/chain thresholds 0.70',
                  'production ScoreBreakdown and scoring dispatch have no V5 F2 contract'],
        scoring_rerun=False,formula_changed=False,config_changed=False,t2_read=False,
        metrics_row_count=len(metrics)))
    print(json.dumps(read(OUT/'summary.json')),flush=True)


if __name__=='__main__':
    {'prepare':prepare,'extract':extract,'evaluate':evaluate}[sys.argv[1]]()
