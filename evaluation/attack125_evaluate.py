"""Post-seal diagnostics only. Never calls a prediction/scoring function."""
from collections import Counter, defaultdict
from datetime import datetime, timezone
from fractions import Fraction
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'evaluation'))
from attack125_baseline import verify_seal, protected_hashes, implementation_hashes, sha, save
from evaluation.framework.v4_semisynthetic_baseline.metrics import stable_match


def read(path):
    return json.loads(Path(path).read_text(encoding='utf8'))


def ratio(n, d):
    return n / d if d else None


def stage_alignment(predictions, truth_members):
    """Support-only alignment, not a claim of complete stage aggregation.

    GT has no frozen Category field. Do not invent a name-to-category mapping.
    Reuse the existing exact maximum-weight, stable-ID tie-break matcher.
    """
    legal = {}
    for p in predictions:
        members = set(p['alert_ids'])
        for gid, target in truth_members.items():
            if members & target:
                legal[p['predicted_stage_id'], gid] = Fraction(len(members & target), len(members | target))
    return dict((g, p) for p, g in stable_match(legal))


def binding_diagnosis(left, right, evidence):
    """Describe lost projections/scopes from frozen facts, never infer aliases."""
    comparisons = []
    for binding in evidence:
        lp = '/' + binding['source_field'].removeprefix('event.').replace('.', '/')
        rp = '/' + binding['target_field'].removeprefix('event.').replace('.', '/')
        lc = [c for c in left.get('contexts', []) if c['raw_pointer'] == lp]
        rc = [c for c in right.get('contexts', []) if c['raw_pointer'] == rp]
        comparisons.append(dict(source_pointer=lp, target_pointer=rp,
            expected_native_value=binding['value'], binding_type=binding['binding_type'],
            source_contexts=lc, target_contexts=rc,
            equal_context_value=any(a['value'] == b['value'] for a in lc for b in rc),
            equal_context_key=any((a['kind'], a['scope'], a['value']) == (b['kind'], b['scope'], b['value'])
                                  for a in lc for b in rc)))
    scoped = [c for c in comparisons if c['equal_context_value'] and not c['equal_context_key']]
    host_refs = [[o for o in a['entity_occurrences'] if o['role'] == 'host'] for a in (left, right)]
    host_id_vs_name = bool(host_refs[0] and host_refs[1] and
        bool({o['raw_pointer'] for o in host_refs[0]} & {'/host_id', '/server_host_id'}) !=
        bool({o['raw_pointer'] for o in host_refs[1]} & {'/host_id', '/server_host_id'}) and
        {o['entity_id'] for o in host_refs[0]} != {o['entity_id'] for o in host_refs[1]})
    if host_id_vs_name:
        layer = 'ENTITY_EXTRACTION_FAILURE'
        explanation = ('HOST identity uses native host_id/server_host_id when present and hostname otherwise. '
            'The two alerts retain the same native hostname but produce different HOST identities; scoped contexts also diverge. '
            'No alias is inferred in this experiment.')
    elif scoped:
        layer = 'BINDING_EXTRACTION_FAILURE'
        explanation = ('Native binding value is projected on both sides, but context scope differs by source_namespace '
            'and/or host. front-data-profiles declares no shared session_scope; equality cannot become an index/evidence match. '
            'This is a deployment/identity compatibility gap, not permission to equate all short IDs globally.')
    else:
        layer, explanation = None, 'No earlier identity/scope break established from these frozen fields.'
    return dict(earliest_identity_layer=layer, explanation=explanation,
                binding_comparisons=comparisons, host_occurrences=host_refs,
                source_process=left.get('process'), target_parent_process=right.get('parent_process'))


def connected_aligned_path(nodes, edges, owners, order):
    """Count contiguous GT transitions along ONE real prediction path.

    Intra-stage edges can connect fragments but add zero GT path length.
    A quotient graph that stitches disconnected prediction fragments is invalid.
    """
    children, indegree = defaultdict(list), dict.fromkeys(nodes, 0)
    for e in edges:
        a, b = e['src_stage'], e['dst_stage']
        children[a].append(b)
        indegree[b] += 1
    ready = sorted(n for n, degree in indegree.items() if degree == 0)
    best = {n: (0, (n,)) for n in nodes}
    seen = 0
    while ready:
        a = ready.pop(0)
        seen += 1
        for b in sorted(children[a]):
            ga, gb = owners.get(a), owners.get(b)
            if ga in order and gb in order and order[gb] - order[ga] in (0, 1):
                count, path = best[a]
                proposal = count + int(ga != gb), path + (b,)
                if (-proposal[0], proposal[1]) < (-best[b][0], best[b][1]):
                    best[b] = proposal
            indegree[b] -= 1
            if indegree[b] == 0:
                ready.append(b)
                ready.sort()
    if seen != len(nodes):
        raise ValueError('prediction_cycle')
    count, path = min(best.values(), key=lambda p: (-p[0], p[1])) if best else (0, ())
    gt_path = []
    for n in path:
        label = owners.get(n)
        if label is not None and (not gt_path or label != gt_path[-1]):
            gt_path.append(label)
    return dict(edge_count=count, node_path=list(path), gt_stage_path=gt_path)


def evaluate(output, truth_path):
    output = Path(output).resolve()
    seal = verify_seal(output)
    destination = output / 'evaluation'
    revision = 1
    while destination.exists():
        revision += 1
        destination = output / ('evaluation_' + str(revision).zfill(2))
    destination.mkdir(exist_ok=False)
    save(destination / 'gt_load_receipt.json', dict(
        prediction_seal_verified=True, runtime_manifest_sha256=seal['runtime_manifest_sha256'],
        prediction_sealed_at=seal['sealed_at'], evaluation_started_at=datetime.now(timezone.utc).isoformat(),
        first_runtime_gt_load=False, runtime_process_finished=True,
        note='All semantic GT loading occurs after the runtime process exited and prediction seal verification.'))
    gt = read(truth_path)  # Sole semantic truth loader in this evaluator.
    runtime = output / 'runtime'
    manifest = read(runtime / 'runtime_manifest.json')
    trace = read(runtime / 'trace_map.json')
    external = {r['event_id']: r['alert_id'] for r in trace}
    reverse = {r['alert_id']: r['event_id'] for r in trace}
    source = {r['alert_id']: r['source'] for r in trace}
    alerts = {a['alert_id']: a for a in read(runtime / 'canonical_alerts.json')}
    communities = read(runtime / 'predicted_communities.json')
    incidents = read(runtime / 'predicted_incidents.json')
    predictions = read(runtime / 'predicted_stages.json')
    nodes = {p['predicted_stage_id']: p for p in predictions}
    edges = read(runtime / 'predicted_edges.json')
    correlations = read(runtime / 'correlation_edges.json')
    gt_members = {s['stage_id']: {external[a] for a in s['member_alert_ids']} for s in gt['stages']}
    truth_owner = {a: g for g, members in gt_members.items() for a in members}
    if len(truth_owner) != sum(len(m) for m in gt_members.values()) or set(truth_owner) != set(alerts):
        raise ValueError('GT_membership_not_unique_full_coverage')
    pred_owner = {aid: n for n, p in nodes.items() for aid in p['alert_ids']}
    inc_owner = {a: i['incident_id'] for i in incidents for a in i['alert_ids']}
    com_owner = {a: c['community_id'] for c in communities for a in c['alert_ids']}
    node_gt_sets = {n: sorted({truth_owner[a] for a in p['alert_ids']}) for n, p in nodes.items()}
    node_gt = {n: gs[0] for n, gs in node_gt_sets.items() if len(gs) == 1}
    support_matches = stage_alignment(predictions, gt_members)
    stage_rows = []
    for s in gt['stages']:
        gid = s['stage_id']
        target = gt_members[gid]
        chosen = support_matches.get(gid)
        members = set(nodes[chosen]['alert_ids']) if chosen else set()
        fragments = sorted({pred_owner[a] for a in target})
        row = dict(gt_stage=gid, gt_name=s['name'], matched_predicted_stage=chosen,
            match_scope='member-support diagnostic; dedicated Stage aggregation absent',
            gt_alert_count=len(target), predicted_alert_count=len(members), overlap_count=len(members & target),
            recall=ratio(len(members & target), len(target)), precision=ratio(len(members & target), len(members)),
            jaccard=ratio(len(members & target), len(members | target)),
            gt_semantic_content=s['name'],
            canonical_category_distribution=dict(Counter(alerts[a]['category'] for a in target)),
            matched_behavior_label=nodes[chosen]['behavior_label'] if chosen else None,
            all_fragment_ids=fragments, fragment_count=len(fragments), STAGE_FRAGMENTATION=len(fragments) > 1,
            STAGE_OVER_MERGE=any(len(node_gt_sets[n]) > 1 for n in fragments),
            full_membership_recovered=members == target,
            support_coverage=ratio(len({a for n in fragments for a in nodes[n]['alert_ids']} & target), len(target)))
        stage_rows.append(row)
    save(destination / 'stage_evaluation.json', dict(stages=stage_rows,
        matching='existing stable_match, one-to-one maximum total exact Jaccard; any positive overlap is legal for support diagnostics',
        formal_stage_metrics_status='unavailable: no dedicated Stage object or GT-name/Category equivalence contract',
        note='Support-matched does not mean complete stage recovery. Per-stage recall/fragmentation and exact membership are reported.'))
    # Load only sealed prediction diagnostics; no scoring is done after truth.
    member_scores, decisions, directions, candidate_keys, clustering = {}, {}, {}, set(), []
    with (runtime / 'diagnostics.jsonl').open(encoding='utf8') as handle:
        for line in handle:
            row = json.loads(line)
            stage = row.get('stage')
            if stage == 'candidate':
                candidate_keys.add(tuple(sorted(row['support_key'])))
            elif stage == 'member_score':
                member_scores[tuple(sorted(row['support_pair']))] = row
            elif stage == 'correlation_decision':
                decisions[tuple(sorted(row['support_key']))] = row
            elif stage == 'chain_direction':
                directions[tuple(sorted(row['support_pair']))] = row
            elif stage == 'clustering':
                clustering.append(row)
    owner = {a: a for a in alerts}
    for group in read(runtime / 'dedupe_groups.json'):
        for a in group['alert_ids']:
            owner[a] = group['representative_alert_id']
    cor_by_key = {tuple(sorted((e['source_alert_id'], e['target_alert_id']))): e for e in correlations}
    edge_rows, failures, used_predictions = [], [], set()
    for gold in gt['edges']:
        ga, gb = gold['source_stage'], gold['target_stage']
        am, bm = gt_members[ga], gt_members[gb]
        # Fragment-aware matching uses actual endpoints AND their actual support.
        # Never turn CorrelationEdge or membership continuity into a ChainEdge.
        compatible = [e for e in edges if node_gt.get(e['src_stage']) == ga and node_gt.get(e['dst_stage']) == gb
                      and set(e['alert_ids']) & am and set(e['alert_ids']) & bm]
        compatible.sort(key=lambda e: (-e['confidence'], e['edge_id']))
        witness_pairs = sorted({(external[b['source_alert_id']], external[b['target_alert_id']])
                                for b in gold['binding_evidence']})
        exact = [e for e in compatible if any({a, b} <= set(e['alert_ids']) for a, b in witness_pairs)]
        chosen = (exact or compatible or [None])[0]
        if chosen:
            used_predictions.add(chosen['edge_id'])
        witness_rows = []
        for a, b in witness_pairs:
            key = tuple(sorted((a, b)))
            rep_key = tuple(sorted((owner[a], owner[b])))
            scored, decision, direction = member_scores.get(key), decisions.get(rep_key), directions.get(key)
            left, right = alerts[a], alerts[b]
            relation_rows = scored.get('evidence', {}).get('relations', []) if scored else []
            evidence = scored.get('evidence', {}) if scored else {}
            audit = evidence.get('evidence_v2', {})
            witness = dict(source_event_id=reverse[a], target_event_id=reverse[b], source_alert_id=a, target_alert_id=b,
                source_raw=left['raw_alert'], target_raw=right['raw_alert'],
                source_contexts=left.get('contexts', []), target_contexts=right.get('contexts', []),
                source_entity_occurrences=left['entity_occurrences'], target_entity_occurrences=right['entity_occurrences'],
                source_relations=left['relations'], target_relations=right['relations'],
                ever_candidate=rep_key in candidate_keys, correlation_score=scored['score'] if scored else None,
                score_values=scored['values'] if scored else None, valid=scored['valid'] if scored else None,
                scoring_rejections=scored['rejection_codes'] if scored else None,
                score_gate=audit.get('gate_reason'), verified_relations=relation_rows,
                correlation_decision=decision, direction_diagnostic=direction,
                same_community=com_owner[a] == com_owner[b],
                community_ids=[com_owner[a], com_owner[b]], same_incident=inc_owner[a] == inc_owner[b],
                incident_ids=[inc_owner[a], inc_owner[b]], predicted_stage_ids=[pred_owner[a], pred_owner[b]],
                formal_correlation_edge_id=cor_by_key.get(rep_key, {}).get('edge_id'),
                expected_semantic_relation=gold['rationale'], expected_binding_evidence=gold['binding_evidence'])
            identity = binding_diagnosis(left, right, gold['binding_evidence'])
            witness['identity_binding_diagnosis'] = identity
            if identity['earliest_identity_layer']:
                layer = identity['earliest_identity_layer']
            elif not witness['ever_candidate']:
                layer = 'CANDIDATE_GENERATION_FAILURE'
            elif not witness['formal_correlation_edge_id']:
                layer = 'CORRELATION_SCORE_FAILURE'
            elif not witness['same_incident']:
                layer = 'INCIDENT_FRAGMENTATION'
            elif direction and any('time' in c or 'chronology' in c for c in direction.get('rejection_codes', [])):
                layer = 'TIME_CONFLICT'
            elif not relation_rows:
                layer = 'EDGE_EVIDENCE_FAILURE'
            elif direction and direction.get('decision') == 'reject':
                layer = 'EDGE_DIRECTION_FAILURE'
            else:
                layer = 'OTHER'
            witness['earliest_observed_blocking_layer'] = layer
            witness['observation_boundary'] = 'Sealed diagnostics only. Missing derived relation is not proof of missing raw evidence.'
            witness_rows.append(witness)
        cross_stage_scored = [r for (a, b), r in member_scores.items()
                              if a in am and b in bm or a in bm and b in am]
        cross_stage_formal = [e for e in correlations if
                             e['support_pair']['alert_id_src'] in am and e['support_pair']['alert_id_dst'] in bm or
                             e['support_pair']['alert_id_src'] in bm and e['support_pair']['alert_id_dst'] in am]
        row = dict(gt_edge=gold['edge_id'], source_stage=ga, target_stage=gb,
            status='RECOVERED' if chosen else 'MISSED', recovered=bool(chosen),
            matched_predicted_edge=chosen['edge_id'] if chosen else None,
            predicted_edge_type=chosen['edge_type'] if chosen else None,
            directed=chosen['directed'] if chosen else None, edge_strength=chosen['edge_strength'] if chosen else None,
            primary_evidence=chosen['primary_evidence'] if chosen else [],
            compatible_fragment_edge_ids=[e['edge_id'] for e in compatible],
            exact_gt_witness_recovered=bool(exact),
            exact_gt_witness_edge_ids=[e['edge_id'] for e in exact],
            stage_match_endpoint_edge_ids=[e['edge_id'] for e in compatible if
                e['src_stage'] == support_matches.get(ga) and e['dst_stage'] == support_matches.get(gb)],
            cross_stage_candidate_member_pair_count=len(cross_stage_scored),
            cross_stage_formal_correlation_count=len(cross_stage_formal),
            max_cross_stage_observed_score=max((r['score'] for r in cross_stage_scored), default=None),
            witness_diagnostics=witness_rows)
        edge_rows.append(row)
        if not chosen:
            failures.append(row)
    save(destination / 'edge_evaluation.json', edge_rows)
    save(destination / 'failure_localization.json', failures)
    order = {s['stage_id']: i for i, s in enumerate(gt['stages'])}
    aligned = connected_aligned_path(nodes, edges, node_gt, order)
    recovered = sum(r['recovered'] for r in edge_rows)
    metrics = dict(TASK_RESULT='ATTACK125_FULL_CHAIN_RECONSTRUCTION_SUCCESS' if aligned['edge_count'] == len(gt['edges'])
        else 'ATTACK125_PARTIAL_CHAIN_RECONSTRUCTION' if recovered else 'ATTACK125_CHAIN_RECONSTRUCTION_FAILED',
        ATTACK125_INPUT_UNCHANGED=True, GT_UNCHANGED=True, MANIFEST_UNCHANGED=True,
        GROUND_TRUTH_USED_AS_RUNTIME_INPUT=False, **manifest['adapter_audit'], **manifest['summary'],
        GT_STAGES=len(gt['stages']), GT_STAGE_MATCHED=len(support_matches),
        GT_STAGE_MISSED=len(gt['stages']) - len(support_matches), PREDICTED_EXTRA_STAGES=len(nodes) - len(support_matches),
        STAGE_RECALL=ratio(len(support_matches), len(gt['stages'])), STAGE_PRECISION=ratio(len(support_matches), len(nodes)),
        STAGE_MATCHING_SCOPE='support-overlap diagnostic only; formal Stage recovery unavailable',
        GT_STAGES_FULL_MEMBERSHIP_RECOVERED=sum(r['full_membership_recovered'] for r in stage_rows),
        GT_EDGES=len(gt['edges']), GT_EDGES_RECOVERED=recovered, GT_DIRECTED_EDGES_RECOVERED=recovered,
        GT_EDGES_RECOVERED_AS_UNDIRECTED=0, GT_EDGES_RECOVERED_AS_WEAK=0,
        GT_EDGES_MISSED=len(gt['edges']) - recovered, PREDICTED_EXTRA_EDGES=len(edges) - len(used_predictions),
        EDGE_RECALL=ratio(recovered, len(gt['edges'])), EDGE_PRECISION=ratio(len(used_predictions), len(edges)),
        EDGE_METRIC_SCOPE='fragment-aware cross-stage member support, one predicted witness per GT edge; attack-only diagnostic, not production precision',
        GT_EXACT_WITNESS_EDGES_RECOVERED=sum(r['exact_gt_witness_recovered'] for r in edge_rows),
        GT_STAGE_MATCH_ENDPOINT_EDGES_RECOVERED=sum(bool(r['stage_match_endpoint_edge_ids']) for r in edge_rows),
        LONGEST_GT_PATH_EDGES=len(gt['edges']), LONGEST_GT_ALIGNED_PATH_EDGES=aligned['edge_count'],
        CHAIN_COVERAGE=ratio(aligned['edge_count'], len(gt['edges'])),
        CHAIN_FRAGMENTATION=aligned['edge_count'] < len(gt['edges']),
        CORRELATION_ALGORITHM_MODIFIED=False, THRESHOLD_MODIFIED=False, ATTACK125_DATA_MODIFIED=False,
        evaluation_coverage=1.0, evaluation_split='attack_only_observational_no_tuning',
        formal_stage_recall=None, formal_stage_precision=None,
        formal_stage_metric_status='unavailable',
        matched_stage_count_is_support_retention_not_stage_reconstruction=True)
    for name, key in [('IDS', 'ids'), ('WAF', 'waf'), ('EDR', 'edr'), ('FIREWALL', 'firewall'),
                      ('AUTH', 'authentication'), ('HOST_AUDIT', 'host_audit')]:
        for statistic in ('input', 'canonical', 'rejected'):
            metrics[name + '_' + statistic.upper()] = manifest['adapter_audit']['by_source'][key][statistic]
    metrics.update(HOST_INPUT=metrics['HOST_AUDIT_INPUT'], HOST_CANONICAL=metrics['HOST_AUDIT_CANONICAL'],
                   HOST_REJECTED=metrics['HOST_AUDIT_REJECTED'])
    # Separate intra-stage edges from extra cross-stage edges: granularity matters.
    distribution = Counter((node_gt.get(e['src_stage'], 'MIXED'), node_gt.get(e['dst_stage'], 'MIXED')) for e in edges)
    chain_report = dict(longest_gt_aligned_path=aligned,
        longest_predicted_path=manifest['summary']['longest_predicted_path'],
        longest_predicted_path_nodes=[nodes[n] for n in manifest['summary']['longest_predicted_path']],
        longest_predicted_path_edges=[e for a, b in zip(manifest['summary']['longest_predicted_path'], manifest['summary']['longest_predicted_path'][1:])
                                     for e in edges if e['src_stage'] == a and e['dst_stage'] == b],
        predicted_edge_gt_distribution=[dict(source_gt=a, target_gt=b, count=n) for (a, b), n in sorted(distribution.items())],
        intra_gt_stage_edge_count=sum(n for (a, b), n in distribution.items() if a == b),
        note='Contiguous recovery is measured on one connected prediction path. GT quotient edges from disconnected fragments are not stitched.')
    save(destination / 'chain_evaluation.json', chain_report)
    save(destination / 'metrics.json', metrics)
    write_report(output, metrics, stage_rows, edge_rows, chain_report, alerts, reverse, node_gt, nodes)
    save(output / 'evaluation_index.json', dict(final_evaluation_directory=destination.name,
        sealed_runtime='runtime', report='REPORT.md'))
    verify_seal(output)
    save(output / 'after_evaluation_hashes.json', dict(protected_files=protected_hashes(), implementation=implementation_hashes(),
        prediction_seal_verified=True, evaluation_completed_at=datetime.now(timezone.utc).isoformat()))
    print(json.dumps({k: v for k, v in metrics.items() if k not in {'by_source', 'rejected', 'longest_predicted_path'}}, indent=2))


def write_report(output, m, stages, edges, chain, alerts, reverse, node_gt, nodes):
    lines = ['# ATTACK125 当前实现 baseline', '',
        '预测在独立进程完成并封存后才读取 GT。未修改生产算法、配置、阈值、Adapter 或冻结数据。', '',
        '**当前无法完整恢复八阶段主链。** 以下 Stage 数量指既有 ChainNode 的投影；当前没有正式 Stage 聚合。', '',
        '## 实际执行范围', '',
        f"- 六源输入 125 → CanonicalAlert {m['CANONICAL_ALERTS']} → 去重事实节点 {m['PREDICTED_STAGE_COUNT']}。",
        f"- 生产路径：候选 {m['CORRELATION_CANDIDATES']} → CorrelationEdge {m['CORRELATION_EDGE_COUNT']} → 受控聚类 Incident {m['INCIDENT_COUNT']} → ChainEdge {m['PREDICTED_DIRECTED_EDGE_COUNT']} → 链快照 {m['PREDICTED_CHAIN_COUNT']}（有边 {m['CHAINS_WITH_EDGES']}）。",
        f"- 独立观察：Community {m['COMMUNITY_COUNT']}（singleton {m['SINGLETON_COMMUNITIES']}，最大 {m['LARGEST_COMMUNITY_SIZE']}）；未接入生产 Incident。",
        '- Community.to_incident 仅有候选兼容转换；当前生产实际采用 cluster_incidents，未手工接线替换。',
        '- 正式 Stage、实/虚 StageEdge、AI Stage fallback 均未实现；未在本轮补建。无向 CorrelationEdge 不冒充无向 StageEdge。',
        '- 当前基线选择现有六源/Community 运行器采用的 algorithm-v5-evidence-semantics.yaml + front-data-sources.yaml、front-data-profiles.yaml、community-v1.yaml；全部有效配置与 hash 已保存。标准 API 的 v5 注册使用另一配置，不能将本实验称为该 API 路由的验收。',
        '- 原始三份需求与 CODEX_TASKS.md 在工作区 docs 缺失，未使用 outputs 中测试副本作为需求原件。', '',
        '## Stage 对比（成员支撑诊断）', '',
        '一对一最大总 Jaccard，稳定 ID 决胜；任何非空成员交集可作支撑匹配。GT 没有冻结 Category 对照，未自造语义标签映射。',
        'GT_STAGE_MATCHED=8 表示八个阶段均保留了可匹配告警支撑，不能解释为八个阶段完成聚合。正式 Stage precision/recall 为 unavailable。', '',
        '| GT | 名称 | GT 告警 | 匹配节点告警 | overlap | recall | precision | 碎片数 |',
        '|---|---|---:|---:|---:|---:|---:|---:|']
    for r in stages:
        lines.append(f"| {r['gt_stage']} | {r['gt_name']} | {r['gt_alert_count']} | {r['predicted_alert_count']} | {r['overlap_count']} | {r['recall']:.4f} | {r['precision']:.4f} | {r['fragment_count']} |")
    lines += ['', f"完整成员恢复的 GT Stage：{m['GT_STAGES_FULL_MEMBERSHIP_RECOVERED']}/8。STAGE_FRAGMENTATION={str(any(r['STAGE_FRAGMENTATION'] for r in stages)).lower()}。", '',
        '## 七条 GT 边', '',
        '主口径允许跨节点碎片恢复，但必须存在本轮实际 ChainEdge 及其跨阶段支撑告警。精确 GT witness 命中另列；不只比较 stage_id。', '',
        '| GT 边 | 状态 | 跨阶段预测边数 | 精确 witness | 最早阻断（GT witness） |',
        '|---|---|---:|---|---|']
    for r in edges:
        layers = ', '.join(sorted({w['earliest_observed_blocking_layer'] for w in r['witness_diagnostics']}))
        lines.append(f"| {r['source_stage']} → {r['target_stage']} | {r['status']} | {len(r['compatible_fragment_edge_ids'])} | {r['exact_gt_witness_recovered']} | {layers} |")
    lines += ['', '两条 RECOVERED 仅表示存在证据支持、方向一致的跨 GT 成员阶段边；精确 GT binding witness 为 0/7。按一对一支撑匹配节点本身的端点算，命中也为 0/7。这些口径全部保留，不能把宽松成员对齐解释为完整阶段或指定因果证据恢复。', '']
    for r in edges:
        if r['recovered']:
            lines += [f"- {r['source_stage']} → {r['target_stage']}：`{r['matched_predicted_edge']}`，{r['predicted_edge_type']}；primary evidence=" +
                json.dumps([dict(relation=x['params']['relation_type'], pointers=x['params']['raw_pointers']) for x in r['primary_evidence']], ensure_ascii=False), '']
    lines += ['', f"Edge recall={m['EDGE_RECALL']:.6f}；Edge precision={m['EDGE_PRECISION']:.6f}（一对一成员支撑诊断）。", f"预测额外边 {m['PREDICTED_EXTRA_EDGES']}；其中 GT 阶段内部边 {chain['intra_gt_stage_edge_count']}。阶段粒度不同使内部边占据大量分母，不能将该值当生产误报率。", '',
        '## 最长链', '', f"最长预测路径 {m['LONGEST_PREDICTED_PATH_EDGES']} 条边、{m['LONGEST_PREDICTED_PATH_STAGES']} 个节点。", '']
    path = chain['longest_predicted_path']
    lines += [' → '.join(f"{node_gt.get(n, 'MIXED')}:{nodes[n]['category']}[{','.join(reverse[a] for a in nodes[n]['alert_ids'])}]" for n in path), '',
        '完整 node_id：`' + ' → '.join(path) + '`。', '',
        f"最长连续 GT 对齐路径：{' → '.join(chain['longest_gt_aligned_path']['gt_stage_path']) or '无'}；{m['LONGEST_GT_ALIGNED_PATH_EDGES']} 条 GT 边；CHAIN_COVERAGE={m['CHAIN_COVERAGE']:.6f}。", '',
        '仅允许同一实际预测路径中的连续 GT 迁移，不能把不同节点碎片上的相邻 GT 边拼成长链。完整节点、边和证据见 chain_evaluation.json。', '',
        '## 最早失败定位', '']
    for r in edges:
        if r['recovered']:
            continue
        lines += [f"### {r['source_stage']} → {r['target_stage']}", '',
            f"GT 关系：{r['witness_diagnostics'][0]['expected_semantic_relation']}", '',
            f"该阶段对实际评分 {r['cross_stage_candidate_member_pair_count']} 对，正式无向关联 {r['cross_stage_formal_correlation_count']} 条，最高已观察分 {r['max_cross_stage_observed_score']}。", '']
        for w in r['witness_diagnostics']:
            lines += [f"- 源/目标告警：`{w['source_event_id']}` → `{w['target_event_id']}`。",
                f"- 最早可观察阻断：**{w['earliest_observed_blocking_layer']}**；ever_candidate={w['ever_candidate']}；score={w['correlation_score']}；valid={w['valid']}；rejections={w['scoring_rejections']}。",
                f"- 字段级原因：{w['identity_binding_diagnosis']['explanation']}",
                f"- same Community={w['same_community']}；same Incident={w['same_incident']}；verified relations={len(w['verified_relations'])}；formal correlation={w['formal_correlation_edge_id']}。",
                f"- 已保留对应预测节点：`{' → '.join(w['predicted_stage_ids'])}`；存在告警节点不等于 Stage 聚合完成。",
                f"- 方向诊断：{json.dumps(w['direction_diagnostic'], ensure_ascii=False) if w['direction_diagnostic'] else '未进入同 Incident 的正式方向候选；无方向评分可报。'}", '']
    lines += ['## 隔离、完整性与复现', '',
        '- before_hashes.json、after_runtime_hashes.json、after_evaluation_hashes.json 保存三个正式文件 SHA-256 和全部 backend/app、configs 文件 hash；运行前后完全一致。',
        '- runtime/read_guard_receipt.json 与 runtime_manifest.json 保存实际读取白名单；runtime 不接收 GT 路径、不导入 evaluation、不读历史输出；仅最终输入、配置、代码/依赖及本轮自生成产物可读。',
        '- GT/manifest 在协调进程中只作不透明字节 hash，不解析、不进入 runtime；语义评测发生在 prediction_seal.json 之后。',
        '- run01–03 为实验运行器白名单/封存校验失败记录，没有评测；run04 是唯一正式封存 baseline。各次未改任何生产实现。',
        '- Grounding 由当前 run_reconstruction 真实执行并通过；runtime_manifest.json 中保留完整结果。所有预测产物在评测后再核验封存 hash。', '',
        '## 下一步', '',
        '优先修 Entity/Binding 的部署身份兼容：先核验并声明有据的 host_id↔hostname 对照及跨源 connection/session 的适用 scope，使已有真实字段能被正确比较。S2→S3 已在 HOST 实体身份处分叉，另外四条漏边的相等原生 binding 值落在不同来源/主机 scope。不能盲目共享所有短 ID；S6 的认证进程还缺 start_time，不能补造完整进程实例。', '',
        '这应作为独立、最小修复任务验收后重测。Community→Incident 衔接和正式 Stage 聚合是后续明确缺口，尚不能宣称已有。不要直接降低 0.65/0.70：五条漏边均已进入 candidate，精确 witness 的 relation=0，部分还有 conflict=0.8，单改阈值不能建立合法方向。Adapter 全量通过，无需重做输入适配。', '',
        '## 评测边界', '',
        'ATTACK125 只有 125 ATTACK、0 BACKGROUND、0 HARD NEGATIVE。本轮仅评价攻击链恢复、阶段支撑、边恢复、连续性和跨源关联；不证明低误报、正常流量区分、Hard Negative rejection 或生产 precision。', '',
        '## 要求的指标', '', '```text']
    excluded = {'by_source', 'rejected', 'longest_predicted_path', 'STAGE_MATCHING_SCOPE', 'EDGE_METRIC_SCOPE'}
    for k, value in m.items():
        if k not in excluded:
            lines.append(k + '=' + ('null' if value is None else str(value).lower() if isinstance(value, bool) else str(value)))
    lines += ['```', '']
    (output / 'REPORT.md').write_text('\n'.join(lines), encoding='utf8')
