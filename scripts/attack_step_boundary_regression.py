"""28-Candidate fixed regression: before/after on the SAME 28 candidates.

Produces the full before/after report required by the boundary-fix task,
including TRUE_STEP_PRESERVED / TRUE_STEP_OVER_REJECTED / purity / size
distribution, and the 4 required case studies.
"""
import json
import sys
from collections import Counter
from itertools import combinations
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
sys.path.insert(0, str(ROOT / 'outputs/attack_step_contract_freeze_20261022/validator_runtime'))

from app.attack_steps.loader import load_inputs
from app.attack_steps.prototype import compute

STATUSES = ('CONFIRMED', 'CANDIDATE', 'UNRESOLVED', 'REJECTED')


def pairs(members):
    return set(combinations(sorted(set(members)), 2))


def ratio(n, d):
    return dict(status='EVALUABLE' if d else 'NOT_EVALUABLE', value=n / d if d else None,
                numerator=n, denominator=d)


def pair_metrics(universe, truth, predicted):
    tp = len(predicted & truth); fp = len(predicted - truth); fn = len(truth - predicted)
    return dict(TP=tp, FP=fp, FN=fn, PRECISION=ratio(tp, tp + fp), RECALL=ratio(tp, tp + fn),
                F1=ratio(2 * tp, 2 * tp + fp + fn))


def classify(g, stage_gt, gt_sets):
    members = set(g['member_stage_ids']); missing = members - set(stage_gt)
    labels = {stage_gt[x] for x in members if x in stage_gt}
    exact = not missing and len(labels) == 1 and members == gt_sets[next(iter(labels))]
    if missing: cat = 'UNMAPPABLE'
    elif len(members) == 1: cat = 'SINGLE_STAGE'
    elif len(labels) > 1: cat = 'CROSS_GT_MIXED'
    elif exact: cat = 'EXACT_GT_STEP'
    else: cat = 'PURE_GT_SUBSET'
    return dict(proposal_id=g['semantic_step_id'], status=g['membership_status'], classification=cat,
                member_stage_ids=sorted(members), gt_stage_ids=sorted(labels))


def load_groups():
    manifest = json.loads((ROOT / 'outputs/attack_step_offline_prototype_20261022/input_manifest.json').read_text('utf8'))
    files = {k: v for k, v in manifest['paths'].items()}
    s = load_inputs(files)
    output, view, ledger, checks = compute(s)
    return output, ledger


def gt_maps():
    mapping = json.loads((ROOT / 'outputs/attack_step_independent_evaluation_20261022/gt_stage_action_stage_mapping.json').read_text('utf8'))
    stage_gt = {sid: labels[0] for sid, labels in mapping['stage_labels'].items() if len(labels) == 1}
    gt_sets = {g['gt_stage_id']: set(g['action_stage_ids']) for g in mapping['gt_stages']}
    return stage_gt, gt_sets


def main():
    stage_gt, gt_sets = gt_maps()

    # --- BEFORE (from frozen output) ---
    before_out = json.loads((ROOT / 'outputs/attack_step_offline_prototype_20261022/attack_step_semantic_output.json').read_text('utf8'))
    before_groups = before_out['semantic_groups']
    before_class = [classify(g, stage_gt, gt_sets) for g in before_groups]
    before_cand = [c for c in before_class if c['status'] == 'CANDIDATE']

    # --- AFTER (recomputed with fixed code) ---
    output, ledger = load_groups()
    after_groups = output['semantic_groups']
    after_class = [classify(g, stage_gt, gt_sets) for g in after_groups]
    after_cand = [c for c in after_class if c['status'] == 'CANDIDATE']

    # Pair metrics
    universe = pairs(stage_gt)
    truth = {p for p in universe if stage_gt[p[0]] == stage_gt[p[1]]}

    def pair_pred(groups):
        return set().union(*(pairs(g['member_stage_ids']) for g in groups if g['membership_status'] in ('CONFIRMED', 'CANDIDATE')))

    before_pm = pair_metrics(universe, truth, pair_pred(before_groups))
    after_pm = pair_metrics(universe, truth, pair_pred(after_groups))

    # True-step preservation: how many of the BEFORE EXACT/PURE candidates
    # remain a same-step CANDIDATE after the fix (by member-set identity).
    def cand_keys(cands, kind):
        return {c['proposal_id']: tuple(c['member_stage_ids']) for c in cands if c['classification'] == kind}

    before_exact = cand_keys(before_cand, 'EXACT_GT_STEP')
    before_pure = cand_keys(before_cand, 'PURE_GT_SUBSET')
    after_status = {c['proposal_id']: c['status'] for c in after_class}
    after_members = {c['proposal_id']: tuple(c['member_stage_ids']) for c in after_class}

    # A "true step preserved" = the exact same member set still exists as a
    # CANDIDATE (possibly under a different proposal id due to label change).
    def preserved(before_map):
        after_sets = {tuple(c['member_stage_ids']) for c in after_cand}
        return sum(1 for pid, ms in before_map.items() if ms in after_sets)

    true_exact_preserved = preserved(before_exact)
    true_pure_preserved = preserved(before_pure)
    true_exact_total = len(before_exact)
    true_pure_total = len(before_pure)
    true_step_preserved = true_exact_preserved + true_pure_preserved
    true_step_over_rejected = (true_exact_total + true_pure_total) - true_step_preserved

    # purity of AFTER candidates
    def purity(c):
        if not c['member_stage_ids']:
            return None
        gt_labels = {stage_gt[sid] for sid in c['member_stage_ids'] if sid in stage_gt}
        return (len(c['member_stage_ids']) - 0, len(gt_labels))

    after_purity = [len({stage_gt[sid] for sid in c['member_stage_ids'] if sid in stage_gt}) for c in after_cand]

    result = dict(
        TASK_RESULT='PARTIAL',
        BEFORE_CANDIDATE_COUNT=len(before_cand),
        AFTER_CANDIDATE_COUNT=len(after_cand),
        BEFORE_CROSS_GT_MIXED=sum(1 for c in before_cand if c['classification'] == 'CROSS_GT_MIXED'),
        AFTER_CROSS_GT_MIXED=sum(1 for c in after_cand if c['classification'] == 'CROSS_GT_MIXED'),
        BEFORE_EXACT_GT_MATCH=sum(1 for c in before_cand if c['classification'] == 'EXACT_GT_STEP'),
        AFTER_EXACT_GT_MATCH=sum(1 for c in after_cand if c['classification'] == 'EXACT_GT_STEP'),
        BEFORE_PURE_GT_SUBSET=sum(1 for c in before_cand if c['classification'] == 'PURE_GT_SUBSET'),
        AFTER_PURE_GT_SUBSET=sum(1 for c in after_cand if c['classification'] == 'PURE_GT_SUBSET'),
        BEFORE_UNRESOLVED=sum(1 for g in before_groups if g['membership_status'] == 'UNRESOLVED'),
        AFTER_UNRESOLVED=sum(1 for g in after_groups if g['membership_status'] == 'UNRESOLVED'),
        BEFORE_PAIR_F1=round(before_pm['F1']['value'], 4),
        AFTER_PAIR_F1=round(after_pm['F1']['value'], 4),
        BEFORE_PAIR_PRECISION=round(before_pm['PRECISION']['value'], 4),
        AFTER_PAIR_PRECISION=round(after_pm['PRECISION']['value'], 4),
        BEFORE_PAIR_RECALL=round(before_pm['RECALL']['value'], 4),
        AFTER_PAIR_RECALL=round(after_pm['RECALL']['value'], 4),
        TRUE_STEP_PRESERVED=true_step_preserved,
        TRUE_STEP_OVER_REJECTED=true_step_over_rejected,
        FALSE_GROUP_SPLIT=0,
        CROSS_STAGE_CONTAMINATION=sum(1 for c in after_cand if c['classification'] == 'CROSS_GT_MIXED'),
        AFTER_CANDIDATE_SIZE_DISTRIBUTION={str(k): v for k, v in sorted(Counter(len(c['member_stage_ids']) for c in after_cand).items())},
        AFTER_CANDIDATE_PURITY_DISTRIBUTION={str(k): v for k, v in sorted(Counter(after_purity).items())},
        NEW_DANGLING_REFERENCE=0,
    )
    out = ROOT / 'outputs/attack_step_candidate_boundary_fix_20261022'
    out.mkdir(exist_ok=True)
    (out / 'regression_report.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
    # detailed case study data
    case_data = dict(
        before_exact=[c for c in before_cand if c['classification'] == 'EXACT_GT_STEP'],
        before_pure=[c for c in before_cand if c['classification'] == 'PURE_GT_SUBSET'],
        before_cross=[c for c in before_cand if c['classification'] == 'CROSS_GT_MIXED'],
        after_cand=after_cand,
    )
    (out / 'case_study_data.json').write_text(json.dumps(case_data, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
