"""Reviewable report from persisted measurements; no replay or truth imports."""
import json
from .common import OUT, ROOT, read, save, sha


def num(v):
    return 'N/A (unscored)' if v is None else f'{v:.9f}' if isinstance(v, float) else str(v)


def table(headers, body):
    def cell(v):
        return str(v).replace('|', '\\|').replace('\n', ' ')
    return '\n'.join(['| ' + ' | '.join(headers) + ' |', '| ' + ' | '.join(['---'] * len(headers)) + ' |'] +
                     ['| ' + ' | '.join(cell(x) for x in row) + ' |' for row in body])


def write_report():
    get = lambda name: read(OUT / (name + '.json'))
    s, audit, freeze = get('summary'), get('gt_edge_audit'), get('freeze_verification')
    cr, ar, dist, rank = (get(n) for n in ('candidate_recall', 'admission_recall', 'score_distribution', 'ranking_metrics'))
    hard, chain, evidence, capability = (get(n) for n in ('hard_negative_audit', 'chain_reconstruction', 'evidence_decomposition', 'source_capability'))
    blind = get('blind_run_manifest')
    lines = ['# V4 Semi-Synthetic Ground Truth Baseline Evaluation', '',
        '**REAL-BACKGROUND + SEMI-SYNTHETIC ATTACK PROGRESSION · development baseline · no tuning**', '',
        f"TASK_RESULT={s['TASK_RESULT']}. Candidate={s['CANDIDATE_GT_EDGES']}/6; scored={s['SCORED_GT_EDGES']}/6; admitted={s['ADMITTED_GT_EDGES']}/6; directed Chain={s['CHAIN_GT_EDGES']}/6. "
        f"Candidate Recall={s['CANDIDATE_RECALL']:.6%}; Admission Recall={s['ADMISSION_RECALL']:.6%}; longest recovered GT path={s['LONGEST_RECOVERED_PATH_EDGES']}/6. "
        f"V5_FORMULA_DESIGN_GATE={s['V5_FORMULA_DESIGN_GATE']} ({s['V5_FORMULA_DESIGN_ANSWER']}).", '',
        '## Frozen baseline and source deployment', '',
        table(['Item', 'Verified value'], [
            ['algorithm_version', freeze['algorithm_version']], ['threshold', '.65 (unchanged)'],
            ['algorithm snapshot hash', freeze['algorithm_config_hash']], ['mapping digest', freeze['mapping_digest']],
            ['historical CPTC run config hash', freeze['expected_historical_run_config_hash']],
            ['current three-source run config hash', freeze['run_config_hash']]]), '',
        freeze['hash_difference_reason'], '',
        'Formal receipt: `outputs/correlation_v4_small/FREEZE_MANIFEST.json`, verified by the existing frozen loader and its execution-equivalence receipt. '
        'The earlier `outputs/correlation_v4/FREEZE_MANIFEST.json` predates the accepted small-slice freeze and is not treated as the final baseline. '
        'No production code, mapping, formula, weight, threshold, candidate policy, schema, clustering or direction guard was changed.', '',
        freeze['scope_policy'], '',
        'The metadata manifest was located at `final/traceback_demo_v1_manifest.json`. Only its source declarations and input contract were projected into the preparation file; '
        'attack times, labels, GT, provenance and scenario definition were inaccessible to the worker. All input timestamps have explicit UTC offsets. '
        'The frozen Suricata and Wazuh adapters were dispatched by native schema/rule groups. No synthetic-field rule or execution-host/asset/account alias was added.', '',
        '## Blind replay and validation', '',
        f"Raw={blind['raw_alert_count']:,}; canonical={blind['canonical_count']:,}; sources={json.dumps(blind['source_counts'])}. "
        f"Blind runtime={blind['total_seconds']:.3f} seconds. Candidates={s['candidate_count']:,}; fully computed original member pairs={s['original_member_score_count']:,}; "
        f"formal CorrelationEdges={s['formal_correlation_edge_count']:,}. All candidate scheduling/scoring completed without resource truncation.", '',
        'Order: preflight manifest/input checks → fresh allowlisted blind worker → ingest → dedupe → entity extraction → candidate generation → full member scoring/admission → '
        'Incident/Chain reconstruction → grounding → SHA-256 sealed artifacts → first semantic GT/provenance load → evaluation. '
        'Blind output was not rerun after truth loading. `blind_run_manifest.json`, `evaluation_started.json`, and `blind/guard_receipt.json` audit this order.', '',
        'Preflight verified declared counts; only after completion did the GT adapter verify all 10,051 provenance line hashes, '
        '21 attack alerts, 30 hard negatives, seven nodes, six edges, the six-edge longest GT path, all references, equality witnesses and declared missing fields. '
        'Opaque preflight integrity hashing included GT bytes but did not parse them or provide them to the algorithm. '
        'The Python audit hook is a tripwire for trusted Python, not an OS sandbox for hostile native extensions.', '',
        '## GT edge lifecycle', '',
        table(['GT edge', 'Stages', 'Candidate', 'Scored', 'Score', 'Gap to .65', 'Gate', 'Admitted', 'Chain', 'Failure'], [
            [e['gt_edge_id'], e['src_stage'] + ' → ' + e['dst_stage'], e['candidate_generated'], e['score_computed'],
             num(e['score']), num(e['score_gap']), e['evidence_gate_reason'], e['admitted'], e['chain_edge_created'], e['final_failure_stage']]
            for e in audit]), '',
        '`BROKEN_AT_SCORING` includes a genuinely computed score that fails the frozen evidence/hard guard. Numeric score admission is separately shown. '
        'Unscored pairs have null scores, not zero. Every full audit includes canonical/external supporting alerts, candidate provenance or absence reason, '
        'unavailable/mismatched evidence, conflicts and the downstream stage reached.', '']
    for e in audit:
        lines += [f"### {e['gt_edge_id']}: {e['final_failure_stage']}", '',
            f"{e['src_gt_node']} → {e['dst_gt_node']}; witness={json.dumps(e['supporting_alerts']['explicit_witness_external'])}.", '']
        if not e['candidate_generated']:
            why = e['candidate_failure_reason']
            lines += [f"Candidate absence: **{why['reason']}**; gap={why['gap_seconds']} s; shared canonical entities={len(why['shared_entity_ids'])}. "
                f"Namespaces={why['source_namespaces']}. Only saved field/window eligibility was inspected; production nomination/scoring was not called.", '']
        else:
            lines += [f"Computed score={num(e['score'])}; gap={num(e['score_gap'])}; evidence gate={e['evidence_gate_reason']}; "
                f"rejection codes={e['scoring_rejection_codes']}. These independently show whether changing a threshold alone could change the decision.", '']
        lines += [table(['GT raw join', 'Source canonical projection', 'Target canonical projection'], [
            [j['source']['raw_field'] + ' → ' + j['target']['raw_field'],
             ', '.join(j['source']['canonical_fields']) or 'RAW_ONLY_UNMAPPED',
             ', '.join(j['target']['canonical_fields']) or 'RAW_ONLY_UNMAPPED'] for j in e['raw_join_projection']]), '',
            f"Frozen witness categories={e['canonical_categories']}. Raw equality is independently verified but is not automatically a canonical shared-entity or attested-propagation assertion.", '']
        lines += ['GT-declared unobservable evidence: ' + ', '.join(e['missing_evidence']['gt_unobservable']) + '.', '',
                  e['downstream_observation'] + '.', '']
    lines += ['## Recall denominators and unlabeled pairs', '',
        'The GT policy explicitly labels only one witness pair per directed transition: **six positive alert pairs**. '
        'The other source-node × target-node combinations are not automatically positive. '
        'Candidate edge recall and explicit positive pair coverage both use the six declared witnesses. No background pair is substituted as GT.', '',
        table(['Metric', 'Numerator', 'Denominator', 'Value'], [
            ['Edge-level Candidate Recall', cr['numerator'], 6, num(cr['value'])],
            ['Explicit alert-pair Candidate Coverage', cr['alert_pair_candidate_coverage']['numerator'], 6, num(cr['alert_pair_candidate_coverage']['value'])],
            ['Admission Recall (actual selected support)', ar['numerator'], 6, num(ar['value'])],
            ['Endpoint-membership candidate supplement (unknown pair labels)', cr['node_endpoint_coverage_supplement']['candidate_pairs'], 54, num(cr['node_endpoint_coverage_supplement']['value'])]]), '',
        f"FULL_GT_EDGES={ar['FULL_GT_EDGES']}; MISSED_GT_EDGES={[x['gt_edge_id'] for x in ar['MISSED_GT_EDGES']]}. "
        'The 54-pair supplement is a structural endpoint diagnostic, not a replacement positive denominator.', '',
        '## Score distributions and separation', '',
        table(['Population', 'Count', 'Min', 'P25', 'Median', 'P75', 'Max', 'Mean'], [
            [label] + [num(d[k]) for k in ('count', 'min', 'P25', 'median', 'P75', 'max', 'mean')]
            for label, d in [('GT explicit positive (scored only)', dist['positive']),
                             ('Explicit hard-negative/attack pairs', dist['hard_negative']),
                             ('All hard-negative-touching pairs (some unknown)', dist['hard_negative_touching_all_candidates']),
                             ('CPTC background pairs (unlabeled)', dist['background_negative_requested'])]]), '',
        f"Only {dist['positive']['count']}/6 explicit positives were actually scored. "
        f"Empirical P(positive score > explicit negative score), ties half={num(dist['separation']['pairwise_order_probability'])}. "
        f"Strict score-range separation={dist['separation'].get('strict_nonoverlap')}. "
        'This selected scored subset cannot establish progression-wide discrimination. No convincing positive/hard-negative separation can be claimed when most GT pairs never reached scoring.', '',
        'The requested background-negative distribution is reported as **unlabeled background**, since real CPTC alerts may include attacks. '
        'Unknown background/hard-hard/other attack pairs are excluded from supervised confusion counts and do not produce a fake overall FPR/precision.', '',
        '## Ranking', '',
        f"Population={rank['population']:,} computed original-member scores, including gate rejects; order={rank['order']}. "
        f"MRR={num(rank['MRR'])}. Missing candidates receive zero reciprocal-rank/Top-K credit; percentile is null. "
        'Percentile is the empirical midrank CDF (higher=better); rank_min/rank_max expose score ties.', '',
        table(['GT edge', 'Best score', 'Global rank', 'Percentile', 'Scored witnesses'], [
            [eid, num(r['score']), r['rank'], num(r['percentile']), r['scored_witness_count']] for eid, r in rank['edges'].items()]), '',
        table(['Top K', 'GT edge hits / 6', 'Recall'], [[k, f"{v['edge_hits']}/6", num(v['edge_recall'])] for k, v in sorted(rank['top_k'].items(), key=lambda item: int(item[0]))]), '',
        'A second ranking in `ranking_metrics.json` collapses all member scores to one maximum-observed score per representative candidate. '
        'It exposes the candidate ranking separately from original alert-pair ranking; neither permits a rejected member to become a formal selected support.', '',
        'Ranks diagnose latent score ordering independently of admission. A high rank cannot bypass the v4 evidence gate or supply unobserved propagation. '
        'The present candidate losses prevent a clean threshold-calibration versus formula comparison for the whole progression.', '',
        '## Hard-negative audit', '',
        f"30 declared hard-negative alerts; touching representative candidates={hard['hard_negative_candidate_count']}; "
        f"touching member scores={hard['hard_negative_member_score_count']}; admitted touching edges={hard['hard_negative_admitted_count']}; "
        f"maximum={num(hard['hard_negative_max_score'])}; mean={num(hard['hard_negative_mean_score'])}. "
        f"Explicit negatives scored={hard['explicit_negative_candidate_count']}/630; explicit admitted FP={hard['explicit_negative_admitted_count']}.", '',
        'All 30 distractors are retained in the per-alert audit, including those with zero candidates. '
        'The touching population describes candidate exposure; only the 630 declared distractor/attack pairs are known negatives. '
        'Zero admitted false positives at this threshold does not prove that the ranking separates attacks from distractors.', '',
        '## Chain reconstruction', '',
        f"Status={chain['status']}; recovered directed GT edges={chain['recovered_gt_edges']}/6; "
        f"longest recovered path={chain['LONGEST_RECOVERED_PATH_EDGES']}/6; GT-induced connected components={chain['connected_components']} "
        '(all seven GT vertices included, isolates counted); exact progression recovered=' + str(chain['exact_progression_recovered']) + '.', '',
        f"GT nodes with one-to-one alert-support matches={chain['recovered_gt_nodes_by_alert_support']}/7 "
        f"(evidence coverage={chain['GT_NODE_EVIDENCE_COVERAGE']:.6%}). "
        f"Exact category+overlap diagnostic CHAIN_NODE_RECALL={chain['CHAIN_NODE_RECALL']:.6%}. "
        'These are separate measurements: retaining alert-backed singleton nodes does not mean recognizing the intended attack stages. '
        'Some GT stages (for example initial_access_attempt) are not frozen Category values. No evaluator invented a stage/category mapping. '
        'Formal incident-conditioned RQ3 node precision/recall is unavailable without that contract and gold Incident alignment.', '',
        f"Actual predicted nodes={chain['actual_chain_node_count']:,}; actual ChainEdges={chain['actual_chain_edge_count']}. "
        f"Correct admitted correlations blocked at Chain={chain['correlation_correct_but_chain_failed']}. "
        'If this list is empty, no observed failure is attributed to reconstruction downstream of a correct admitted edge. '
        'Nevertheless, scenario-authored causal attribution with missing request/process/session linkage does not satisfy the frozen explicit-propagation guard.', '',
        '## Actual v4 evidence-family decomposition', '',
        'The scoring families are exactly the implementation keys **time, entity, relation, behavior, source**. '
        'The implementation also records observation families (for example TEMPORAL, ENTITY_IDENTITY, RULE_METADATA); these are not extra scoring weights. '
        'For each observable family k, m_k=w_k*s_k. Q=Σm_k/available_weight; M=Σm_k/total_configured_weight; '
        'raw=quality_factor*Q+mass_factor*M−weighted conflict−weighted duplicate. The seven legacy signed contributions are audit values and do not sum to the v4 final score.', '']
    for e, d in evidence.items():
        lines += [f'### {e}', '']
        if d['status'] != 'available':
            lines += ['No explicit GT candidate witness was scored. Family contributions and score are **null**, not invented by rescoring after labels.', '']
            continue
        lines += [table(['Family', 'Observable', 'Strength', 'Weight', 'Weighted mass', 'Quality contribution', 'Mass contribution'], [
            [k, v['observable'], num(v['strength']), num(v['weight']), num(v['weighted_evidence_mass']),
             num(v['quality_score_contribution']), num(v['mass_score_contribution'])] for k, v in d['families'].items()]), '',
            f"Raw evidence mass={num(d['raw_evidence_mass'])}; available_weight={num(d['available_weight'])}; total configured={num(d['total_configured_weight'])}; "
            f"normalized quality={num(d['normalized_quality'])}; evidence mass={num(d['evidence_mass'])}; penalties={d['penalties']}; "
            f"raw={num(d['raw_total'])}; final={num(d['final_score'])}. Exact unrounded recomputation passed.", '',
            f"Gate={d['gate_reason']}; primary evidence={d['primary_evidence']}; topology diagnostic={d['network_diagnostic']}. "
            f"Holding current non-temporal observations fixed, algebraic temporal-best ceiling={num(d['frozen_non_temporal_evidence_score_ceiling'])}. "
            'This is an equation bound, not a second production run or a claim that stronger facts exist.', '', d['missingness_semantics'], '']
    lines += ['## Source observability and projection', '',
        'Source capability is assessed from the actual saved records and frozen projection. **ABSENT_BUT_OBSERVABLE** means an available v4 dimension mismatches; '
        '**UNOBSERVABLE_BY_SOURCE** here means missing in this pair’s frozen input, not a universal assertion about the vendor. '
        'Raw-only observations are separately retained and never counted as a production match.', '']
    for e, c in capability.items():
        lines += [f"- **{e}**: GT observable={', '.join(c['gt_declared_observable_evidence'])}; GT unobservable={', '.join(c['gt_declared_unobservable_evidence'])}."]
    lines += ['', 'The native Wazuh host shapes can retain agent identity, audit auid and parent executable in raw_alert while the frozen projection does not '
        'necessarily expose them as host/account/parent-instance entities. An agent address/name cannot be promoted to execution-host identity without an appropriate source contract; '
        'a parent executable name is not a parent process instance. Frozen category mappings must also be distinguished from the vendor descriptions. '
        'These are projection/semantic-contract limitations, separate from source-intrinsic absent account/process/session data in network alerts.', '',
        'Missing families are excluded from Q but remain uncredited in M; available mismatches and frozen metadata/destination-role reliability further constrain actual scores. '
        'The saved computed-positive ceiling is reported above. No all-six-edge formula ceiling is asserted, because unscored pairs have no legitimate decomposition. '
        'No unavailable field is treated as an explicit conflict.', '',
        '## Cause assessment and V5 gate', '',
        f"Primary assessment: **{s['primary_cause']}**. Failure counts={s['failure_stage_counts']}. "
        'The evidence distinguishes A (no candidate) from B (raw-to-canonical/category projection gaps), C (missing shared scope or unobserved causal identifiers), '
        'D (measured v4 family/gate/score behavior), E (threshold-only hypothesis), and F (correct admitted edge lost during reconstruction). '
        'A/B/C can be demonstrated from input/projection/candidate evidence. D is measured only on scored witnesses; E is not established for all six; '
        'F is not observed without a correct admitted support.', '',
        f"**V5_FORMULA_DESIGN={s['V5_FORMULA_DESIGN_ANSWER']} / {s['V5_FORMULA_DESIGN_GATE']}** for a formula change justified by this run alone. "
        'This is a conservative assessment for this task, not a new frozen project acceptance rule. '
        'The baseline supplies actionable diagnostic evidence, but candidate and projection/observability losses leave most true transitions without scores. '
        'Resolve independent ingestion/deployment contracts and validate broader progression coverage in a separately authorized blind experiment before attributing progression failure to the formula. '
        'No rerun after label inspection, tuning, GT special-case or V5 implementation occurred. Design leads only: `V5_DESIGN_FINDINGS.json`.', '',
        '## Tests and integrity', '']
    focused = OUT / 'tests_focused.log'
    regression = OUT / 'tests_regression.log'
    for title, path in [('Focused tests', focused), ('Affected regression', regression)]:
        if path.exists():
            lines += [f"{title}: " + next((x for x in reversed(path.read_text(encoding='utf8').splitlines()) if 'passed' in x), 'see log'), '']
    classification = OUT / 'regression_failure_classification.json'
    if classification.exists():
        c = read(classification)
        lines += [f"The existing Task 06.6 historical freeze-receipt test fails on {len(c['files'])} files. "
            f"All flagged bytes equal this task’s entry inventory={c['all_unchanged_this_task']}. "
            'The receipt was not edited and the broader suite is not fully green. This does not invalidate the independently verified v4 algorithm/config/mapping freeze.', '']
    check = get('integrity_verification')
    lines += [f"External dataset repository: **{check['dataset']['status']}**, {check['dataset']['file_count']} files, including .git, no additions/deletions/byte changes. "
        f"Production/config/docs/frontend: **{check['production']['status']}**, {check['production']['file_count']} files unchanged. "
        'No Git metadata exists in the main workspace; SHA-256 receipts record integrity.', '',
        'Reproduction phases (repository root; this output is single-use for blind execution):', '',
        '```powershell',
        '.venv/Scripts/python.exe -m evaluation.framework.v4_semisynthetic_baseline prepare',
        '.venv/Scripts/python.exe -m evaluation.framework.v4_semisynthetic_baseline blind',
        '.venv/Scripts/python.exe -m evaluation.framework.v4_semisynthetic_baseline evaluate',
        '.venv/Scripts/python.exe -m evaluation.framework.v4_semisynthetic_baseline verify',
        '.venv/Scripts/python.exe -m evaluation.framework.v4_semisynthetic_baseline report', '```', '',
        '`evaluate` may be repeated against the same sealed blind artifacts for report/metric repairs; it cannot rerun production. '
        '`blind` refuses once the completed manifest or evaluation-start marker exists. '
        'File inventory: `manifest.json`; detailed stage evidence: `blind/diagnostics.jsonl.gz`; all required JSON reports are in this directory.', '',
        '## TASK_RESULT', '', '```text']
    for k in ('TASK_RESULT', 'DATASET_INTEGRITY', 'GROUND_TRUTH_LEAKAGE', 'GT_EDGES', 'CANDIDATE_GT_EDGES',
              'SCORED_GT_EDGES', 'ADMITTED_GT_EDGES', 'CHAIN_GT_EDGES', 'CANDIDATE_RECALL', 'ADMISSION_RECALL',
              'LONGEST_GT_PATH_EDGES', 'LONGEST_RECOVERED_PATH_EDGES', 'GT_MAX_SCORE', 'GT_MEDIAN_SCORE',
              'HARD_NEGATIVE_MAX_SCORE', 'V4_MODIFIED', 'THRESHOLD', 'V5_FORMULA_DESIGN_GATE'):
        value = s[k]
        if k in ('CANDIDATE_GT_EDGES', 'SCORED_GT_EDGES', 'ADMITTED_GT_EDGES', 'CHAIN_GT_EDGES'):
            value = str(value) + '/6'
        if isinstance(value, bool):
            value = str(value).upper()
        lines.append(k + '=' + str(value))
    lines += ['```', '']
    (OUT / 'V4_SEMISYNTHETIC_BASELINE_REPORT.md').write_text('\n'.join(lines), encoding='utf8')


def manifest():
    files = {}
    for p in sorted(OUT.rglob('*')):
        if p.is_file() and p.name != 'manifest.json' and not any('pytest' in part for part in p.relative_to(OUT).parts):
            files[p.relative_to(OUT).as_posix()] = sha(p)
    sources = sorted((ROOT / 'evaluation/framework/v4_semisynthetic_baseline').glob('*.py'))
    sources.append(ROOT / 'evaluation/tests/test_v4_semisynthetic_baseline.py')
    save(OUT / 'manifest.json', {'version': 'v4-semisynthetic-baseline-evaluation-1',
        'task_result': read(OUT / 'summary.json')['TASK_RESULT'], 'files': files,
        'source_hashes': {p.relative_to(ROOT).as_posix(): sha(p) for p in sources},
        'blind_manifest_sha256': sha(OUT / 'blind_run_manifest.json'),
        'labels_used_for_production': False, 'v4_modified': False})
