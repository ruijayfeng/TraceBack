"""Cross-dataset outputs and conclusions constrained by actual completeness."""

from collections import Counter
import json
from pathlib import Path

from .common import capture_integrity, freeze_recipe, ratio, read_json, truth_tripwire, write
from .diagnosis import diagnose_scene, ingress_observation_coverage, ingress_window_coverage, reproduce_observation_pointer_gap


TAXONOMY = [
    ('F1', 'Sparse Alert Schema', '缺少一个或多个可用实体维度', 'DATA_LIMITATION', 'source schema / minimum useful fields'),
    ('F2', 'No Shared Entity', '已评分成员对无共享实体，且没有接受关联', 'EXPECTED_BEHAVIOR', 'inspect missing identity context before algorithm changes'),
    ('F3', 'High-Frequency Shared Entity', '共享实体被冻结规则标记 hot 且候选被拒绝', 'EXPECTED_BEHAVIOR', 'obtain a specific independent observation; preserve common-infrastructure guard'),
    ('F4', 'Source Semantic Mismatch', '源类别/rule/signature 无跨源语义等价依据', 'UNRESOLVED', 'inspect vendor mapping coverage independently of labels'),
    ('F5', 'Missing Network Context', 'v3 network_fields_unavailable，未接受', 'DATA_LIMITATION', 'collect actual endpoint/flow context from upstream alerts'),
    ('F6', 'Missing Host Context', '成员对至少一侧 host 缺失', 'DATA_LIMITATION', 'upstream execution/target host context; no invented asset aliases'),
    ('F7', 'Temporal Fragmentation', '有连续性依据但超过该通道有效窗', 'UNRESOLVED', 'separate unobserved steps from justified time-window limitations'),
    ('F8', 'Candidate Admission Miss', '窗内至少两类共享上下文事实但未入候选的有界复核案例', 'ALGORITHM_LIMITATION', 'audit frozen Top-K ranks and admission recall with independent pair GT'),
    ('F9', 'Insufficient Independent Evidence', '独立证据 gate 未通过，候选未接受', 'EXPECTED_BEHAVIOR', 'test whether credible sparse pairs lose evidence; retain independence guard'),
    ('F10', 'Relation Mapping Gap', '接受无向边但无已核验传播关系', 'EXPECTED_BEHAVIOR', 'obtain ordered operation/lineage evidence; absence alone is not a mapping bug'),
    ('F11', 'Threshold Boundary', '0.50≤score<0.65 的拒绝候选', 'UNRESOLVED', 'label independent near-threshold pairs before assessing 0.65'),
    ('F12', 'Dedupe Information Loss', '去重成员信息丢失必须有可复现证据；同组不等于丢失', 'UNRESOLVED', 'compare retained member fields and group winner; no dedupe tuning'),
    ('F13', 'Public Infrastructure / Common Server Noise', 'hot 实体、无独立主证据且未接受', 'EXPECTED_BEHAVIOR', 'retain shared-server safeguards and review any admitted counterexamples'),
    ('F14', 'Detection Metadata Similarity Without Attack Continuity', 'metadata_dominated 且未接受', 'EXPECTED_BEHAVIOR', 'preserve collapsed metadata support; similarity alone is insufficient'),
    ('F15', 'Cross-source Identity Resolution Failure', '跨产品候选无共享实体且拒绝；身份失败尚待资产/realm事实确认', 'UNRESOLVED', 'verify deployment identities; never infer aliases from attack labels'),
    ('F16', 'Frozen Candidate Resource Budget', 'admitted 超过冻结 max_candidate_pairs，可靠完整评测阻塞', 'ALGORITHM_LIMITATION', 'measure resource scalability in a separately authorized implementation stage'),
    ('F17', 'Full-population Index Resource Exhaustion', '全场景实体/索引/候选步骤真实资源中止', 'UNRESOLVED', 'reproduce resource footprint; distinguish host capacity and index representation cost'),
    ('F18', 'Supported Source Envelope / Observation Pointer Mismatch', 'Wazuh 包装 Suricata 有 flow/protocol/完整 endpoint tuple，但冻结 source_type 指针读取不到', 'IMPLEMENTATION_DEFECT', 'review the supported envelope/pointer integration after manual acceptance; no Task C fix'),
]


def apply_execution_progress(result, directory):
    """Recover verified stage receipts, never turn partial scoring into a result."""
    path = Path(directory)/'worker.log'
    if result['status'] == 'completed' or not path.exists():
        return result
    receipt = {'log_ref': f"{result['dataset']}/worker.log", 'full_scoring_population_complete': False}
    with path.open(encoding='utf-8') as handle:
        for line in handle:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if not isinstance(row, dict) or row.get('dataset') != result['dataset']:
                continue
            if row.get('stage') == 'candidates':
                receipt['generated_candidate_pair_count'] = row['count']
                receipt['last_actual_stage'] = 'scoring_setup'
            elif row.get('stage') == 'scoring':
                receipt.update(last_actual_stage='scoring', verified_candidate_count_lower_bound=row['verified_candidates'],
                               partial_edge_count_at_last_progress=row['accepted_edges'])
            elif row.get('stage') == 'failed':
                receipt['worker_reported_failure'] = row.get('reason')
            elif row.get('stage') not in {'blocked', 'completed', None}:
                receipt['last_actual_stage'] = row['stage']
    result['execution_progress'] = receipt
    if receipt.get('generated_candidate_pair_count') is not None:
        result.setdefault('counts', {})['candidate_pair_count'] = receipt['generated_candidate_pair_count']
    return result


def summary_row(result, ingress):
    c = result.get('counts', {})
    stats = result.get('candidate_stats') or {}
    n = c.get('representative_count')
    edges, candidates, incidents = c.get('correlation_edge_count'), c.get('scored_candidate_count'), c.get('incident_count')
    singleton, multi = c.get('singleton_incident_count'), c.get('multi_alert_incident_count')
    scores = result.get('scores', {}).get('all_scored_candidates', {})
    cross = sum(r['count'] for r in result.get('source_pairs', []) if r['decision'] == 'accept'
                and len(set(r['source_pair'].split(' ↔ '))) > 1)
    completed = result['status'] == 'completed'
    def optional_ratio(x, y):
        return ratio(x, y) if x is not None and y is not None else None
    return {'dataset': result['dataset'], 'status': result['status'],
        'blocked_stage': result.get('execution_progress', {}).get('last_actual_stage', result.get('blocked_stage')),
        'blocked_stage_checkpoint': result.get('blocked_stage'), 'blocked_reason': result.get('blocked_reason'),
        'execution_progress': result.get('execution_progress'),
        'raw_alert_count': ingress.get('raw_alert_count'), 'canonical_alert_count': ingress.get('canonical_alert_count'),
        'representative_count': n, 'dedupe_group_count': c.get('dedupe_group_count'),
        'dedupe_reduction_ratio': optional_ratio(ingress.get('canonical_alert_count', 0)-n, ingress.get('canonical_alert_count')) if n is not None else None,
        'entity_count': c.get('entity_count'),
        'candidate_pair_count': c.get('candidate_pair_count'), 'scored_candidate_count': candidates,
        'potential_indexed_neighbors': stats.get('potential_pair_stats', {}).get('unique_potential_pairs'),
        'policy_pruned_count': stats.get('policy_pruned_count'), 'resource_truncated_count': stats.get('resource_truncated_count'),
        'correlation_edge_count': edges, 'incident_count': incidents,
        'singleton_incident_count': singleton, 'multi_alert_incident_count': multi,
        'raw_singleton_incident_count': c.get('raw_singleton_incident_count'),
        'chain_edge_count': c.get('chain_edge_count'), 'high_risk_singleton_count': c.get('high_risk_singleton_count'),
        'candidate_per_representative': optional_ratio(c.get('candidate_pair_count'), n), 'edge_per_representative': optional_ratio(edges, n),
        'edge_admission_rate': optional_ratio(edges, candidates), 'singleton_ratio': optional_ratio(singleton, incidents),
        'multi_alert_ratio': optional_ratio(multi, incidents),
        'chain_edge_ratio': optional_ratio(c.get('chain_edge_count'), edges),
        'max_score': scores.get('max'), 'P95_score': scores.get('P95'),
        'cross_source_edges': cross if completed else None,
        'config_hash': result.get('config_hash'), 'mapping_digest': result.get('mapping_digest'),
        'algorithm_version': result.get('algorithm_version'), 'dataset_digest': result.get('dataset_digest'),
        'ratios_definition': {'candidate_per_representative': 'generated candidate pairs/representatives',
            'edge_admission_rate': 'formal edges/scored candidates',
            'singleton_ratio': 'one-representative incidents/all incidents (dedupe wrappers not counted as multi-alert)',
            'multi_alert_ratio': 'multi-representative incidents/all incidents', 'chain_edge_ratio': 'directed chain edges/formal correlation edges'},
        'unknown_counts_are_null': True}


def funnel(row, result):
    values = [(k, row.get(k)) for k in ('representative_count', 'potential_indexed_neighbors', 'candidate_pair_count', 'scored_candidate_count')]
    scores = result.get('scores', {}).get('all_scored_candidates', {})
    above = sum(v for k, v in scores.get('buckets', {}).items() if float(k[1:k.index(',')]) >= .65) if scores else None
    values += [('score_ge_0_65', above), ('correlation_edge_count', row['correlation_edge_count']),
               ('multi_alert_incident_count', row['multi_alert_incident_count'])]
    result_rows = []
    previous = None
    for name, value in values:
        convertible = name not in {'representative_count', 'potential_indexed_neighbors', 'multi_alert_incident_count'}
        rate = ratio(value, previous) if convertible and value is not None and previous is not None else None
        result_rows.append({'stage': name, 'count': value, 'conversion_rate': rate,
            'elimination_fraction': 1-rate if rate is not None else None,
            'conversion_status': 'available' if rate is not None else 'not_applicable_mixed_units_or_unknown'})
        previous = value
    return {'dataset': row['dataset'], 'status': row['status'], 'stages': result_rows,
        'notes': ['Representative→pair retrieval is a density, not a probability conversion.',
            'score>=0.65 includes gate-rejected highest observed member scores; formal edges need the frozen independent evidence gate.',
            'Edge→Incident changes units; incident count/edge count is not an edge survival rate.',
            'policy_pruned is expected admission policy; resource_truncated is incomplete execution.']}


def generate_report(root, destination):
    root, destination = Path(root), Path(destination)
    datasets, config, settings, recipe = freeze_recipe(root)
    if read_json(destination/'recipe.json') != recipe:
        raise ValueError('report_recipe_changed')
    inventory = read_json(destination/'dataset_inventory.json')
    # Complete this independent field inventory / production reproducer before
    # opening labels. Alternate observed paths never enter production config.
    raw_observations = {}
    for item in inventory:
        scene = item['dataset']
        directory = destination/scene
        observed = ingress_observation_coverage(directory, config)
        samples = observed.pop('samples', [])
        with truth_tripwire(root):
            observed['reproductions'] = [reproduce_observation_pointer_gap(s, config, settings, recipe['config_hash']) for s in samples]
        if samples:
            write(directory/'observation_gap_reproduction.json', {'dataset': scene, 'config_hash': recipe['config_hash'],
                'samples': samples, 'reproductions': observed['reproductions'], 'ground_truth_used': False,
                'command': f'.venv/Scripts/python.exe -m evaluation.framework.correlation_v3_multidataset --reproduce-observation-gap outputs/correlation_v3_multidataset/{scene}/observation_gap_reproduction.json'})
        raw_observations[scene] = observed
        print(json.dumps({'dataset': scene, 'stage': 'offline_raw_observation_audit',
            'complete_tuple_pointer_misses': observed.get('complete_tuple_pointer_miss_count')}), flush=True)
    # Production has ended. Ground truth is now read exclusively by evaluation.
    from evaluation.io.ait_ads import load_ait_ads_ground_truth
    try:
        gt = load_ait_ads_ground_truth(root)
    except Exception as exc:
        gt = {'status': 'unavailable', 'records': [], 'limitations': [type(exc).__name__+':'+str(exc)]}
    write(destination/'labels_readiness.json', {k: v for k, v in gt.items() if k != 'records'})
    results, ingresses, summaries = {}, {}, []
    near, audits, missed, profiles, temporal_coverage = {}, {}, {}, {}, {}
    for item in inventory:
        scene = item['dataset']
        directory = destination/scene
        ingress = read_json(directory/'preflight.json') if (directory/'preflight.json').exists() else {}
        result = read_json(directory/'result.json') if (directory/'result.json').exists() else {
            'dataset': scene, 'status': 'blocked', 'blocked_stage': 'adapter', 'blocked_reason': item['status']}
        result = apply_execution_progress(result, directory)
        if result.get('config_hash') not in (None, recipe['config_hash']):
            raise ValueError('cross_dataset_actual_config_mismatch')
        if result['status'] == 'completed':
            near[scene], audits[scene], missed[scene] = diagnose_scene(directory, result, gt, config)
        else:
            unknown = {'status': 'unavailable', 'reason': result.get('blocked_reason'),
                       'limitation': 'no complete scored population; missing counts are null, not zero'}
            near[scene], audits[scene], missed[scene] = unknown.copy(), unknown.copy(), unknown.copy()
        results[scene], ingresses[scene] = result, ingress
        temporal_coverage[scene] = ingress_window_coverage(directory, gt, scene)
        print(json.dumps({'dataset': scene, 'stage': 'offline_window_coverage',
            'temporal_overlap_fraction': temporal_coverage[scene].get('temporal_overlap_fraction')}), flush=True)
        row = summary_row(result, ingress)
        summaries.append(row)
        coverage = ingress.get('field_coverage', {}).get('field_presence_rate', {})
        entities = result.get('entity_distribution', {})
        profiles[scene] = {'status': 'available_statistics' if entities else 'partial_adapter_statistics_only',
            'shared_entity_density': {'pair_exposures': entities.get('shared_entity_pair_exposures'),
                'denominator_all_pairs': row['representative_count']*(row['representative_count']-1)//2 if row['representative_count'] else None,
                'note': 'entity exposure overlap is not a unique shared-pair density'},
            'cross_alert_entity_reuse_ratio': entities.get('cross_alert_entity_reuse_ratio'),
            'field_completeness': coverage, 'cross_source_entity_overlap_count': len(entities['cross_source_entities']) if entities.get('cross_source_entities') is not None else None,
            'flow_availability': coverage.get('flow_id'), 'session_availability': coverage.get('session'),
            'temporal_locality': {'potential_pairs': row['potential_indexed_neighbors'],
                'time_range': [ingress.get('min_timestamp'), ingress.get('max_timestamp')]},
            'assessment': 'inspect these raw statistics; no weighted correlatability score or unvalidated HIGH/MEDIUM/LOW rank',
            'limitation': 'shareable fields are necessary but not sufficient for independent attack continuity'}
    fields = {}
    for scene, ingress in ingresses.items():
        from copy import deepcopy
        coverage = deepcopy(ingress.get('field_coverage', {}))
        observed = raw_observations[scene]
        if coverage and observed['status'] == 'available_full_ingress':
            coverage['frozen_flow_pointer_presence_rate'] = coverage['field_presence_rate']['flow_id']
            coverage['frozen_flow_pointer_presence_count'] = coverage['field_presence_count']['flow_id']
            coverage['field_presence_rate']['flow_id'] = observed['raw_embedded_flow_presence_rate']
            coverage['field_presence_count']['flow_id'] = observed['raw_embedded_flow_presence_count']
            for src, row in observed['by_source'].items():
                coverage['field_presence_rate_by_source'][src]['flow_id'] = row['raw_embedded_flow_presence_rate']
            coverage['flow_id_scope'] = 'stored native/wrapped raw fields at already declared pointer paths; frozen v3 pointer visibility separately; no new schema field/entity'
            profiles[scene]['field_completeness'] = coverage['field_presence_rate']
            profiles[scene]['flow_availability'] = coverage['field_presence_rate']['flow_id']
            profiles[scene]['frozen_flow_pointer_availability'] = coverage['frozen_flow_pointer_presence_rate']
        fields[scene] = coverage
    entity_rows = {s: r.get('entity_distribution', {'status': 'unavailable', 'reason': r.get('blocked_reason')}) for s, r in results.items()}
    source_rows = {s: {'source_alert_count': i.get('source_alert_count'),
        'source_alert_count_population': 'unique canonical alerts; raw import counts are in preflight.inputs',
        'source_representative_count': r.get('source_representative_count'),
        'source_representative_participation': r.get('source_representative_participation'),
        'source_entity_coverage': r.get('source_entity_coverage'),
        'source_candidate_participation': r.get('source_candidate_participation'),
        'source_edge_participation': r.get('source_edge_participation'), 'source_pairs': r.get('source_pairs'),
        'host_network_pairs': r.get('host_network_pairs'),
        'note': 'Suricata wrapped in Wazuh is counted by CanonicalAlert.source_type; collector origin remains separately in source_namespace'}
        for s, r in results.items() for i in [ingresses[s]]}
    modes = []
    for code, title, definition, diagnosis, improvement in TAXONOMY:
        per_scene = {}
        for scene, result in results.items():
            counts = result.get('candidate_taxonomy', {})
            if code in counts:
                per_scene[scene] = counts[code]
            elif code == 'F8' and missed[scene].get('status') == 'available_bounded_review':
                per_scene[scene] = missed[scene]['reason_counts'].get('NO_CANDIDATE', 0)
            elif code == 'F7' and missed[scene].get('status') == 'available_bounded_review':
                per_scene[scene] = len(missed[scene].get('temporal_fragmentation_examples', []))
            elif code == 'F16':
                per_scene[scene] = (result.get('candidate_stats') or {}).get('resource_truncated_count')
            elif code == 'F17':
                per_scene[scene] = int('memory' in result.get('blocked_reason', '').lower() or 'commit' in result.get('blocked_reason', '').lower())
            elif code == 'F18':
                per_scene[scene] = raw_observations[scene].get('complete_tuple_pointer_miss_count')
            else:
                per_scene[scene] = None
        representatives = []
        for scene, audit in near.items():
            for case in audit.get('top_rejected', [])[:3]:
                if code == 'F11' and .5 <= case['final_score'] < .65 or code == 'F9' and not case['evidence_gate_passed']:
                    representatives.append({'dataset': scene, 'support_key': case['support_key'], 'final_score': case['final_score'],
                        'audit_ref': f'{scene}/near_threshold_audit.json'})
        if code == 'F8':
            representatives = [{'dataset': s, **c} for s, m in missed.items() for c in m.get('cases', []) if c['failure_reason'] == 'NO_CANDIDATE'][:8]
        if code in {'F16', 'F17'}:
            representatives = [{'dataset': s, 'blocked_stage': r.get('blocked_stage'), 'blocked_reason': r.get('blocked_reason')}
                               for s, r in results.items() if per_scene[s]]
        if code == 'F18':
            representatives = [{'dataset': s, **r, 'minimal_reproduction_ref': f'{s}/observation_gap_reproduction.json'}
                               for s, o in raw_observations.items() for r in o.get('reproductions', []) if r['confirmed_envelope_pointer_mismatch']]
        modes.append({'code': code, 'name': title, 'definition': definition, 'trigger_conditions': definition,
            'datasets': [s for s, n in per_scene.items() if n], 'case_counts_by_dataset': per_scene,
            'count_scope': 'bounded nearest-pair review' if code in {'F7', 'F8'} else 'resource-omitted pairs' if code == 'F16'
                           else 'resource-blocked datasets' if code == 'F17' else 'full unique canonical ingress with actual complete wrapped event fields' if code == 'F18'
                           else 'scored-candidate diagnostic proxy; modes overlap',
            'known_case_count': sum(n for n in per_scene.values() if n is not None)
                                if any(n is not None for n in per_scene.values()) else None,
            'coverage_incomplete': any(n is None for n in per_scene.values()), 'representative_cases': representatives,
            'diagnosis': diagnosis, 'data_limitation': diagnosis == 'DATA_LIMITATION',
            'algorithm_design_limitation': diagnosis == 'ALGORITHM_LIMITATION', 'suspected_implementation_bug': code == 'F18' and bool(representatives),
            'potential_improvement_direction': improvement, 'implemented': False,
            'limitation': 'proxy occurrence is not proof of a true missed/false correlation; unmeasured modes remain null'} )
    defects = [{'dataset': s, 'minimal_reproduction': c, 'action': 'record only; no production fix'}
               for s, audit in audits.items() for c in audit.get('cases', []) if c.get('suspicious_edge')]
    defects += [{'dataset': s, 'code': 'SOURCE_ENVELOPE_POINTER_MISMATCH', 'diagnosis': 'IMPLEMENTATION_DEFECT',
        'affected_complete_tuple_alert_count': o['complete_tuple_pointer_miss_count'],
        'minimal_reproduction_ref': f'{s}/observation_gap_reproduction.json',
        'minimal_reproduction': o['reproductions'][0], 'action': 'record only; no production/config fix',
        'scope': 'confirmed observation visibility defect; downstream missed-edge counts remain unresolved'}
        for s, o in raw_observations.items() if any(r['confirmed_envelope_pointer_mismatch'] for r in o.get('reproductions', []))]
    completed = [r for r in summaries if r['status'] == 'completed']
    blocked = [r for r in summaries if r['status'] != 'completed']
    status = 'C_V3_IMPLEMENTATION_DEFECT_FOUND' if defects else 'C_EVALUATION_BLOCKED' if blocked else (
        'C_V3_MIXED_FAILURE_MODES' if any(m['code'] == 'F8' and m['known_case_count'] for m in modes) else 'C_V3_STABLE_DATA_LIMITED')
    recommendations = [
        {'priority': 'P0' if blocked else 'P2', 'area': 'Evaluation completeness / full-population resource scalability',
         'evidence': [{'dataset': r['dataset'], 'reason': r['blocked_reason']} for r in blocked],
         'recommendation': 'first obtain complete frozen-v3 runs for every ready scene; profile index/candidate memory and do not change thresholds to escape resource limits',
         'implementation_authorized_by_task_c': False},
        {'priority': 'P1', 'area': 'Upstream evidence availability and source identity declarations',
         'evidence_ref': 'field_coverage.json; entity_distribution.json; source_distribution.json',
         'recommendation': 'verify actual flow/host/process/session context and independent source topology; no inferred asset aliases', 'implementation_authorized_by_task_c': False},
        {'priority': 'P2', 'area': 'Candidate admission and independent pair validation',
         'evidence': {s: m.get('reason_counts') for s, m in missed.items()},
         'recommendation': 'manually validate factual missed candidates then reproduce nearest ranks and frozen Top-K before proposing admission changes', 'implementation_authorized_by_task_c': False},
        {'priority': 'deferred', 'area': '0.65 threshold / scoring / relation mapping redesign',
         'evidence_ref': 'near_threshold_audit.json; edge_audit.json',
         'recommendation': 'no threshold recommendation without independent pair labels and complete runs; keep v3 frozen', 'implementation_authorized_by_task_c': False}]
    if any(d.get('code') == 'SOURCE_ENVELOPE_POINTER_MISMATCH' for d in defects):
        recommendations.insert(0, {'priority': 'P0', 'area': 'Supported Suricata-in-Wazuh envelope pointer defect',
            'evidence_ref': 'raw_observation_coverage.json; failure_modes.json; */observation_gap_reproduction.json',
            'recommendation': 'manually accept the existing envelope/pointer defect first, then separately authorize a fix and rerun frozen comparisons; do not redesign scoring/thresholds to compensate',
            'implementation_authorized_by_task_c': False})
    answers = {
        'Q1': '无法判断 russellmitchell 是否异常：存在未完成场景。' if blocked else '按下面跨场景表比较 singleton、gate 与字段，不能仅凭边数断言异常。',
        'Q2': '完整场景的真实边数见总表；阻塞场景为 null，不代表没有关联。',
        'Q3': '独立证据缺失和 gate 拒绝均有可核验统计；未完成场景阻止全局数据/算法主因定论。' if blocked else '字段覆盖、hot、gate 与有界漏关联案例共同诊断；singleton 本身不是算法失败。',
        'Q4': '缺部署身份或独立拓扑时跨源拒绝可能预期；source pair 表与共享实体统计不能替代独立真值。',
        'Q5': 'near-threshold 数量并不证明 0.65 有结构性问题；高数值但 gate 不通过的候选也不能靠降低阈值接受。未改阈值。',
        'Q6': '当前可靠评测首先受全场景资源/预算或接入阻塞限制；已完成场景需再按 funnel 分离提名、证据 gate 和数值分数。' if blocked else '由逐场景 funnel 和 evidence distribution 定位；缺字段、独立主证据及稀有度是不同层次，不应全部归因于 threshold。'}
    if completed:
        totals = {'scored': sum(r['scored_candidate_count'] for r in completed),
            'formal_edges': sum(r['correlation_edge_count'] for r in completed),
            'gate_rejected': sum(results[r['dataset']].get('candidate_taxonomy', {}).get('F9', 0) for r in completed),
            'near_threshold': sum(results[r['dataset']].get('candidate_taxonomy', {}).get('F11', 0) for r in completed)}
        answers['Q3'] += f" 已完成人口：{totals['scored']} 个已评分候选，{totals['gate_rejected']} 个独立证据 gate 拒绝，{totals['formal_edges']} 条正式边。"
        answers['Q5'] += f" [0.50,0.65) 拒绝候选 {totals['near_threshold']} 个；需结合其 gate 状态复核。"
        benchmark = next((r for r in completed if r['dataset'] == 'russellmitchell'), None)
        if benchmark:
            larger = [r['dataset'] for r in completed if r['dataset'] != 'russellmitchell' and r['correlation_edge_count'] > benchmark['correlation_edge_count']]
            answers['Q2'] = f"russellmitchell 完整本次执行 {benchmark['correlation_edge_count']} 条正式边；更多边的已完成场景：{larger or '无'}。" + ('阻塞场景无法比较。' if blocked else '')
    if any(d.get('code') == 'SOURCE_ENVELOPE_POINTER_MISMATCH' for d in defects):
        answers['Q3'] = '已确认一种实际字段存在但冻结 observation 指针未读取的实现集成缺陷，不能将这些缺失解释为数据天然稀疏。其对 singleton/漏边的影响尚未完成全量验证；其他真实缺字段与资源限制单列。'
        answers['Q6'] += ' 已确认的 source envelope/pointer 缺陷位于观测身份与证据读取接口：Wazuh 包装 Suricata 保留 /data/flow_id、/data/proto，但 v3 按 suricata 顶层路径查找；network continuity 所需 event/protocol 因此不可见。'
    before = read_json(destination/'protected_before.json')
    print(json.dumps({'dataset': 'all', 'stage': 'verify_protected_sha256', 'protected_files': len(before)}), flush=True)
    after = capture_integrity(root)
    changed = [p for p, digest in before.items() if after.get(p) != digest]
    if changed:
        raise ValueError('protected_production_or_snapshot_changed:'+str(changed))
    integrity = {'protected_file_count': len(before), 'changed_files': changed, 'passed': not changed,
        'production_source_config_threshold_snapshots_unchanged': True,
        'git_metadata': 'unavailable in this checkout; byte SHA-256 comparison is used',
        'no_gt_in_production': 'runtime file-open tripwire during all production invocations plus existing isolation regressions',
        'scope': 'existing backend/app, configs, docs, inputs, data/processed, outputs/analyses, v3 and incremental snapshots/artifacts'}
    outputs = {'dataset_summary.json': summaries,
        'cross_dataset_comparison.json': {'recipe': recipe, 'datasets': summaries, 'answers': answers, 'TASK_C_RESULT': status,
            'completed_dataset_count': len(completed), 'blocked_dataset_count': len(blocked),
            'limitations': ['Window metadata cannot establish absolute FP/FN, pairwise precision/recall or causal chain accuracy.',
                           'Unknown algorithm counts are null; no sampling or partial run is labelled a complete scenario.']},
        'field_coverage.json': fields, 'entity_distribution.json': entity_rows, 'source_distribution.json': source_rows,
        'candidate_funnel.json': {r['dataset']: funnel(r, results[r['dataset']]) for r in summaries},
        'score_distribution.json': {s: r.get('scores', {'status': 'unavailable', 'reason': r.get('blocked_reason')}) for s, r in results.items()},
        'evidence_distribution.json': {s: r.get('evidence', {'status': 'unavailable', 'reason': r.get('blocked_reason')}) for s, r in results.items()},
        'near_threshold_audit.json': near, 'edge_audit.json': audits, 'missed_correlation_audit.json': missed,
        'failure_modes.json': {'modes': modes, 'algorithm_defect_candidates': defects, 'overlapping_counts_must_not_be_summed': True},
        'correlation_potential.json': profiles, 'v4_recommendations.json': recommendations, 'integrity.json': integrity,
        'labels_window_coverage.json': temporal_coverage, 'raw_observation_coverage.json': raw_observations}
    outputs['index_resource_probes.json'] = {s: r.get('index_resource_probe') for s, r in results.items()}
    for name, value in outputs.items():
        write(destination/name, value)
    for scene in results:
        for name, data in (('near_threshold_audit.json', near[scene]), ('edge_audit.json', audits[scene]), ('missed_correlation_audit.json', missed[scene])):
            (destination/scene).mkdir(parents=True, exist_ok=True)
            write(destination/scene/name, data)
    def cell(value):
        if value is None:
            return 'null'
        return f'{value:.6f}' if isinstance(value, float) else str(value)
    lines = ['# Correlation v3 Multi-Dataset Evaluation & Failure Mode Analysis', '',
        f'`TASK_C_RESULT = {status}`', '',
        f'扫描 {len(summaries)} 个场景；完整执行 {len(completed)} 个，阻塞/失败 {len(blocked)} 个。',
        '各场景完整原始数据 Adapter 校验在独立生产运行之前完成；未修改算法、权重、阈值、关系、guard、聚类或 triage。', '',
        '## Frozen recipe and reproducibility', '', f"- algorithm_version: `{recipe['algorithm_version']}`",
        f"- config_hash: `{recipe['config_hash']}`", f"- mapping_digest: `{recipe['mapping_digest']}`",
        '- threshold: 0.65; clustering/chain threshold: 0.70',
        '- 所有场景使用同一份包含既有全部 namespace/timezone 的有效配置和源快照；不同场景告警从未同时传入算法。',
        '- 完整 recipe、原始 SHA-256、Canonical 输入摘要、领域对象摘要和阶段日志保存在对应目录。',
        '- 运行：`.venv/Scripts/python.exe -m evaluation.framework.correlation_v3_multidataset`；有界结果恢复使用 `--resume`。', '',
        '## Cross-dataset comparison', '',
        '| Dataset | Status | Raw | Canonical | Representatives | Candidate pairs | Scored candidates (complete) | Edges | Incidents | Singleton % | Multi % | Chain edges | Max | P95 | Cross-source edges | High-risk singleton |',
        '|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    for r in summaries:
        values = [r[k] for k in ('dataset', 'status', 'raw_alert_count', 'canonical_alert_count', 'representative_count', 'candidate_pair_count',
            'scored_candidate_count', 'correlation_edge_count', 'incident_count')]
        values += [r[k]*100 if r[k] is not None else None for k in ('singleton_ratio', 'multi_alert_ratio')]
        values += [r[k] for k in ('chain_edge_count', 'max_score', 'P95_score', 'cross_source_edges', 'high_risk_singleton_count')]
        lines.append('| '+' | '.join(cell(v) for v in values)+' |')
    lines += ['', 'Singleton 按一个去重代表定义；原始单告警 Incident 另列于 dataset_summary.json。资源中止的未知计数为 null，不计作 0。', '',
        '## Field / entity / source coverage', '',
        '| Dataset | Host | Account | Session | Process | Flow ID | Src IP | Dst IP | Source counts (canonical) |',
        '|---|---:|---:|---:|---:|---:|---:|---:|---|']
    for scene, coverage in fields.items():
        f = coverage.get('field_presence_rate', {})
        lines.append('| '+scene+' | '+' | '.join(cell(f.get(k)) for k in ('host', 'account', 'session', 'process', 'flow_id', 'src_ip', 'dst_ip'))
            +' | '+str(ingresses[scene].get('source_alert_count'))+' |')
    lines += ['', 'flow_id 按已存储 raw_alert 的 native/wrapped 已声明路径统计；冻结 v3 实际指针可见率另列。Frozen Schema 没有 FLOW Entity，不增字段。',
        '字段缺失、可观测但不匹配、弱匹配和依赖抑制分开统计；source 差异不等于检测独立。',
        'Entity 的 df 以完整去重代表为人口；没有完整实体阶段的场景不填虚构 representative coverage。', '',
        '## Candidate funnel / score / evidence', '',
        'candidate_funnel.json 区分潜在邻居、局部提名、全局预算、完整评分、数值门槛、独立证据 gate 和事件单位。',
        'score_distribution.json 包含所有已评分候选（无合法成员时采用最高已观测拒绝成员）及合法胜出成员两种人口，含 P25/P50/P75/P90/P95/P99、均值、极值及固定 buckets。',
        'Candidate 与 Formal Edge 证据分布分开；NOT_APPLICABLE 可能为双方缺失或依赖抑制，不能全部解释为源字段天然不存在。', '',
        '## Near-threshold / high-score audits', '',
        'near_threshold_audit.json 是精确 Top-N 拒绝候选与按 source/gate/network 的代表样本。每个案例记录两个原告警、角色、共享实体、未舍入分、实际 v3 contribution、缺失、gate 和绑定 raw 指针。',
        'edge_audit.json 检查事实重复、metadata 主导、hot 公共实体、localhost、独立主证据和 raw 指针。公共实体出现本身不认定误关联；必须复核另一个主证据。', '',
        '## Offline labels and missed correlations', '',
        f"labels status: `{gt['status']}`；labels 只在生产结果冻结后由 evaluation/io 读取。",
        '官方 labels.csv 是 scenario/attack/start/end 区间元数据，没有逐告警/逐 pair/Incident/方向真值；pairwise Precision/Recall 为 null + unavailable，quality evaluation coverage 为 0。',
        '窗外告警视为未标注，不能当 background。跨不重叠窗口边为 Potential False Correlation 复核线索，不是绝对 FP。',
        '漏关联筛查要求同窗、具体 account/session/process/resource 与另一共享上下文事实，并在冻结实体窗内；仅时间相同不入选。候选未提名与 gate/低分拒绝分开。筛查有界，不冒充完整 FN/Recall。', '',
        'labels_window_coverage.json 对完整冻结 ingress 流做离线时间窗覆盖计数；评分阻塞的场景也可验证时间对齐。窗外仍为未标注，quality coverage 仍为 0。', '',
        '## Failure Mode Taxonomy / Data vs Algorithm', '',
        '| Code | Failure mode | Diagnosis | Known proxy cases | Coverage incomplete |', '|---|---|---|---:|---|']
    lines += [f"| {m['code']} | {m['name']} | {m['diagnosis']} | {cell(m['known_case_count'])} | {m['coverage_incomplete']} |" for m in modes]
    lines += ['', '这些是可复核诊断条件，不是互斥真值标签；计数不能相加。未观测 F4/F7/F12 保持 null / UNRESOLVED；不以没有样本证明不存在。', '',
        '## Stability questions', '']
    lines += [f'- **{k}**：{v}' for k, v in answers.items()]
    if blocked:
        lines += ['', '## Explicit blockers', ''] + [f"- {r['dataset']}: stage={r['blocked_stage']}; {r['blocked_reason']}" for r in blocked]
        lines += ['', 'worker.log 已确认完成生成的 CandidatePair 可计数；partial scoring 进度只作为下界收据，不计作完整分布或正式发布边。',
                  'dataset_summary.json 的 execution_progress 保留最后实际阶段、已核验候选下界与 worker 原始异常；checkpoint 阶段另列。']
        lines += ['', '| Dataset | Existing index bit storage lower bound MiB | Available commit at probe MiB |',
                  '|---|---:|---:|']
        for scene, result in results.items():
            probe = result.get('index_resource_probe') or {}
            lines.append(f"| {scene} | {cell(probe.get('MiB'))} | {cell(probe.get('available_commit_mb_at_probe'))} |")
        lines += ['', '这是已有实现分配成本的下界，排除告警模型、字典、候选、其他索引副本；不是采样估计。没有完成探针的场景保持 null。',
                  '资源中止发生在当前主机容量下；不能直接定性为评分设计错误，也不能将未执行的边审计解释为没有缺陷。']
    lines += ['', '## Algorithm Defect Candidate', '',
        f'共记录 {len(defects)} 个场景级异常候选（含 source envelope/pointer 集成复现）；未完成场景没有正式边审计，不证明没有其他缺陷。最小复现详见 failure_modes.json。任何生产问题仅记录，不修复。',
        'F18 区分 raw 中实际存在 flow/protocol/完整 endpoint tuple 与冻结指针不可见，不能归因于数据天然缺字段。复现仅用一个真实 CanonicalAlert，不伪造第二条告警或评分人口；实际漏边数量未验证。', '',
        '## Correlation v4 Recommendation (not implemented)', '']
    lines += [f"- {r['priority']} {r['area']}: {r['recommendation']}" for r in recommendations]
    regression_path = destination/'regression.json'
    regression = read_json(regression_path) if regression_path.exists() else {'status': 'pending'}
    lines += ['', '## Regression and repository protection', '',
        f'原有生产/配置/原始数据/历史快照 {len(before)} 个文件 SHA-256 全部一致。',
        f'回归记录：`regression.json`，当前状态：`{regression.get("status")}`。仅实际通过计为通过；opt-in skips 单列。',
        '当前 checkout 无 Git 元数据，因此 Files Changed 按新增评测模块/测试与 SHA-256 验证汇报。']
    if regression.get('environment_failures'):
        lines += ['', '回归中发生过的环境失败及后续重跑均保存在 regression.json；失败日志没有删除，也不计作通过。']
    lines += ['', 'Task C 在此停止；未启动 Correlation v4。', '', f'`TASK_C_RESULT = {status}`', '']
    (destination/'MULTIDATASET_EVALUATION_REPORT.md').write_text('\n'.join(lines), encoding='utf-8')
    return status
