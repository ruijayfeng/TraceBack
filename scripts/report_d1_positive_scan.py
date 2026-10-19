"""Read-only interpretation and compact reproducibility receipts for D.1."""
from collections import Counter
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import d1_positive_scan as d1
from app.correlation.edges import correlation_version
from app.models.base import resolve_pointer
from app.utils.stable_id import raw_fingerprint,content_digest


def table(headers,rows):
    return '\n'.join(['| '+' | '.join(headers)+' |','| '+' | '.join('---' for _ in headers)+' |']+
        ['| '+' | '.join(str(x).replace('|','/') for x in row)+' |' for row in rows])


def tests(path):
    tree=ET.parse(path).getroot()
    suites=tree.findall('testsuite')
    return {k:sum(int(s.get(k,0)) for s in suites) for k in ('tests','failures','errors','skipped')}


def audit(summary,top):
    checks=Counter()
    issues=[]
    for window in top['windows']:
        for pair in window['pairs']:
            checks['pairs_checked']+=1
            for aid,item in pair['raw_alerts'].items():
                if raw_fingerprint(item['raw_alert'])!=item['raw_fingerprint']:
                    issues.append('raw_hash:'+aid)
            for ref in pair['resolved_evidence_refs']:
                if ref['alert_id'] not in {pair['alert_a_id'],pair['alert_b_id']}:
                    issues.append('unbound_ref')
                value=resolve_pointer(pair['raw_alerts'][ref['alert_id']]['raw_alert'],ref['pointer'])
                if value!=ref['resolved_value']:
                    issues.append('ref_value_mismatch')
                checks['resolved_pointers_checked']+=1
            ev=pair['evidence']
            keys=[e['fact_key'] for e in ev['evidence']]
            if len(keys)!=len(set(keys)):
                issues.append('duplicate_evidence_fact')
            if len(ev['evidence_families'])!=len(set(ev['evidence_families'])):
                issues.append('duplicate_evidence_family')
            if set(ev['matched_evidence'])&set(ev['suppressed_dimensions']):
                issues.append('consumed_dimension_reinforced')
            if pair['source_independence']!='confirmed_independent' and ev['family_strengths']['source']!=0:
                issues.append('unknown_or_same_origin_source_reward')
            if pair['formal_edge_accepted']:
                checks['formal_pairs_checked']+=1
                if pair['score']<.65 or not pair['guard_result']['valid'] or not ev['evidence_gate_passed']:
                    issues.append('formal_admission')
                if not ev['primary_evidence'] or ev['metadata_dominated']:
                    issues.append('metadata_only_formal_edge')
                hot={e['entity_id'] for e in ev['entity_reliability'] if e['hot']}
                for fact in ev['evidence']:
                    if fact['role']=='primary' and hot.intersection(fact['entity_ids']):
                        issues.append('hot_primary_evidence')
                a,b=[pair['raw_alerts'][aid] for aid in (pair['alert_a_id'],pair['alert_b_id'])]
                if a['source_namespace']==b['source_namespace'] and a['raw_fingerprint']==b['raw_fingerprint']:
                    issues.append('exact_duplicate_formal_pair')
    for w in summary['windows']:
        if w['status']!='COMPLETE':
            continue
        ids=[e['edge_id'] for e in w['formal_edges']]
        if len(ids)!=len(set(ids)):
            issues.append('duplicate_formal_edge')
        members=[a for i in w['multi_alert_incidents'] for a in i['alert_ids']]
        if len(members)!=len(set(members)):
            issues.append('overlapping_multi_incidents')
        if not w['grounding']['valid']:
            issues.append('production_grounding_failed')
    return dict(checks=dict(checks),issues=issues,passed=not issues,
        scope='all exported Top20 and formal pairs; complete production grounding on every completed window',
        limitations=['No GT attack confirmation or pairwise accuracy estimated.',
            'Evidence fact independence is not statistical observation independence or confirmed source independence.',
            'Candidate duplication additionally covered by frozen Candidate v1.1 regression and admitted/scored count check.'])


def main():
    out=d1.OUT
    s=d1.read_json(out/'scan_summary.json')
    top=d1.read_json(out/'top_pairs.json')
    if not s['finished']:
        raise ValueError('D1_scan_not_complete')
    checks=audit(s,top)
    d1.atomic_json(out/'correctness_audit.json',checks)
    if not checks['passed']:
        raise ValueError('D1_IMPLEMENTATION_DEFECT_FOUND:'+str(checks['issues']))
    configs={}
    for scene in s['scenarios']:
        loaded=d1.load_dataset(ROOT,scene_id=scene,config_version='v4')
        d1.frozen(loaded)
        snapshot={'algorithm':loaded.config.snapshot,'sources':{k:v.snapshot() for k,(_,v) in sorted(loaded.sources.items())}}
        configs[scene]=dict(config_hash=content_digest(snapshot),mapping_digest=loaded.config.mapping_digest,
            algorithm_version=correlation_version(loaded.config),config_snapshot=snapshot)
        if any(w.get('config_hash')!=configs[scene]['config_hash'] for w in s['windows'] if w['scenario']==scene and w['status']=='COMPLETE'):
            raise ValueError('window_snapshot_hash_mismatch')
    d1.atomic_json(out/'effective_config_snapshots.json',configs)
    complete=[w for w in s['windows'] if w['status']=='COMPLETE']
    best=s['recommended_candidate']
    best_window=next((w for w in top['windows'] if best and (w['scenario'],w['start_time'],w['end_time'])==(best['scenario'],best['start_time'],best['end_time'])),None)
    selected_pair=max((p for p in best_window['pairs'] if p['formal_edge_accepted']),key=lambda p:p['score']) if best_window else None
    high=s['best_scored_pair']
    highformal=s['best_formal_pair']
    regression=tests(out/'regression.xml')
    focused=tests(out/'d1_tests.xml')
    freeze=d1.read_json(out/'freeze_after.json')
    before=d1.read_json(out/'freeze_before.json')['protected_files']
    newly_added=set(d1.protected_files())-set(before)
    unexpected_new=[p for p in sorted(newly_added) if p!='scripts/report_d1_positive_scan.py']
    if unexpected_new:
        raise ValueError('D1_unexpected_protected_file_additions:'+str(unexpected_new))
    plan=d1.read_json(out/'search_plan.json')
    scenes=table(['Scenario','完成/尝试窗口','候选评分','正式边(窗口计数)','>=0.70正式边','multi-fact Incident'],[
        [scene,f"{sum(w['scenario']==scene for w in complete)}/{sum(w['scenario']==scene for w in s['windows'])}",
         sum(w['scored_pair_count'] for w in complete if w['scenario']==scene),
         sum(w['formal_edge_count'] for w in complete if w['scenario']==scene),
         sum(w['cluster_eligible_edge_count'] for w in complete if w['scenario']==scene),
         sum(w['multi_alert_incident_count'] for w in complete if w['scenario']==scene)] for scene in s['scenarios']])
    scale_rows=table(['窗口秒','完成窗口','候选评分','正式边','multi-fact Incident'],[
        [seconds,sum(w['duration_seconds']==seconds for w in complete),
         sum(w['scored_pair_count'] for w in complete if w['duration_seconds']==seconds),
         sum(w['formal_edge_count'] for w in complete if w['duration_seconds']==seconds),
         sum(w['multi_alert_incident_count'] for w in complete if w['duration_seconds']==seconds)] for seconds in s['window_scales_seconds']])
    dist=table(['诊断 cutoff','所有候选最高有效/拒绝分','有效 pair（gate/guard通过）','正式边'],[
        [c,s['cutoffs'][str(c)],s['valid_pair_cutoffs'][str(c)],s['formal_edge_cutoffs'][str(c)]] for c in d1.CUTS])
    known=[]
    for w in complete:
        if w['scenario']=='wilson' and w['start_time']==d1.POLICY['known_replay']['start']:
            pairs=next(x['pairs'] for x in top['windows'] if (x['scenario'],x['start_time'],x['end_time'])==(w['scenario'],w['start_time'],w['end_time']))
            original=next((p for p in pairs if {p['alert_a_id'],p['alert_b_id']}=={'alt_97baaab5114e871b42e2c163b5409be8f6e5ee95b7af3ba0dc5488e88299d5d5','alt_d49253b55d0d3875c5e3d5d9c70643996efbd1a0fcf5a1024e93d5bfb31d8673'}),None)
            known.append([w['duration_seconds'],w['raw_alert_count'],w['representative_alert_count'],
                f"{original['score']:.9f}" if original else '未进入Top20（不据此声称未入候选）',w['formal_edge_count'],w['multi_alert_incident_count'],
                '; '.join(f"df={e['frequency']}/N={e['population']}, r={e['rarity']:.6f}, hot={e['hot']}" for e in original['evidence']['entity_reliability']) if original else '详见逐窗口诊断'])
    comparison=table(['窗口秒','raw','representative','已知pair分','正式边','multi Incident','原pair实体频率'],known)
    graph_rows=table(['Scenario / UTC区间','nodes / edges','components / singleton','multi component / 最大规模','聚类拒绝规则'],[
        [f"{w['scenario']} [{w['start_time']},{w['end_time']})",f"{w['graph']['number_of_nodes']}/{w['graph']['number_of_edges']}",
            f"{w['graph']['connected_components']}/{w['graph']['singleton_count']}",
            f"{w['graph']['multi_node_component_count']}/{w['graph']['largest_component_size']}",
            dict(Counter(x['rule_id'] for x in w['clustering_diagnostics'] if x['decision']=='reject'))]
        for w in complete if w['formal_edge_count']])
    pair_text='未发现正式边。'
    score_explanation=''
    if highformal:
        p=highformal
        ev=p['evidence']
        pair_text=f"""最高正式边：`{p['alert_a_id']}` ↔ `{p['alert_b_id']}`，未舍入分 `{p['score']:.12f}`。
窗口：{p['scenario']} [{p['window_start']}, {p['window_end']}) UTC；两端时间：{p['timestamp_a']} / {p['timestamp_b']}；时间差 {p['time_delta_seconds']} 秒。
类型：{p['relation_type']}；方向映射：`{p['relation_mapping_result']}`。无五类显式关系时，仅解释共同调查上下文，不称传播、因果或攻击已确认。
Primary：{p['primary_evidence']}；Supporting：{p['supporting_evidence']}。
Families：{p['evidence_families']}；strong evidence count={p['independent_evidence_count']}；source independence={p['source_independence']}。
"""
        score_explanation=f"""五家族权重 `{json.dumps(ev['family_weights'])}`，强度 `{json.dumps(ev['family_strengths'])}`。
`matched_weight={ev['matched_weight']:.12f}`，`available_weight={ev['available_weight']:.12f}`，quality=`{ev['normalized_quality']:.12f}`，mass=`{ev['evidence_mass']:.12f}`。
按冻结 v4：`0.65 × quality + 0.35 × mass − 0.45 × C − 0.40 × D`；C={p['values']['conflict']}，D={p['values']['duplicate']}，结果 `{p['score']:.12f}`。
Metadata 仅提供已封顶的 supporting 信号；同源 unknown 不奖励独立来源；未观测传播和互补维度无奖励。实体具体值/角色、指针、完整原告警、Reason、未舍入审计和候选准入 provenance 均保存于 top_pairs.json。
"""
    best_text=f"""`RECOMMENDED_DEMO_CANDIDATE`：{best['scenario']} [{best['start_time']}, {best['end_time']}) UTC，时长 {best['duration_seconds']} 秒。
raw / canonical / representative = {best['raw_alert_count']} / {best['canonical_alert_count']} / {best['representative_alert_count']}。
正式边 {best['formal_edge_count']}；cluster-eligible {best['cluster_eligible_edge_count']}；multi-fact Incident {best['multi_alert_incident_count']}；总 Incident {best['incident_count']}。
来源 {best['sources_present']}，跨源正式边 {best['cross_source_formal_edge_count']}，primary families {best['evidence_quality_summary']['primary_families']}。
推荐排序先看真实 multi-fact Incident、跨源关联、可读边结构，再看较小告警量/窗口；未按最高分直接选择。
相关正式边：{[e['edge_id'] for e in best['formal_edges']]}。全部告警保留；其余代表占比 `{(best['representative_alert_count']-len({a for e in best['formal_edges'] for a in (e['source_alert_id'],e['target_alert_id'])}))/best['representative_alert_count']:.2%}` 仅是图零度代理，不称良性污染率。
""" if best else '未推荐候选。'
    gap_reason=f"本次 {s['gap_formal_edges']} 条窗口级正式边处于 0.65–0.70；{s['cluster_eligible_edges']} 条进入聚类阈值。"
    if not s['cluster_eligible_edges'] and s['formal_edges']:
        gap_reason+=' 聚类拒绝诊断直接为 clustering.edge_threshold；当前主要边界是自然评分强度不足以达到0.70。展示图确有连接，但聚类资格图无这些边；两桥、TargetSet、跨度和规模保护尚未成为这些边的限制，不能将其归因为两桥失败或实现异常。'
    else:
        gap_reason+=' 达0.70后是否合并须读正式 clustering_diagnostics 的 TargetSet、独立支撑数、hard conflict与跨度检查；连通分量本身不是 Incident。'
    highest_text=f"总体最高候选分 `{high['score']:.12f}`，pair `{high['alert_a_id']}` / `{high['alert_b_id']}`，窗口 {high['scenario']} [{high['window_start']},{high['window_end']})。gate={high['guard_result']}，正式接受={high['formal_edge_accepted']}。" if high else '没有候选分数。'
    if high:
        hev=high['evidence']
        highest_text+=f"\n该最高候选的五家族强度为 `{json.dumps(hev['family_strengths'])}`，available_weight={hev['available_weight']:.12f}，matched_weight={hev['matched_weight']:.12f}，quality={hev['normalized_quality']:.12f}，mass={hev['evidence_mass']:.12f}；依同一quality/mass公式得分，primary={hev['primary_evidence']}，supporting={hev['supporting_evidence']}。数值超过0.70的真实pair确实存在，但若gate未通过仍不能作为强正式关联或Incident证据。"
    report=f"""# D.1 Correlation v4 Positive Feasibility Report

最终状态：`{s['status']}`。推荐：`{s['final_recommendation']}`。
本报告是冻结算法下的真实数据可行性扫描，不是准确率 benchmark；结论限于完成的 bounded 窗口和 Candidate v1.1 准入集合。未读取任何真实 labels.csv、attacks.log、Gold Chain；不声称全 AIT-ADS 不存在正例。

## 冻结、方法与可复现边界

算法：`{d1.EXPECTED['algorithm_version']}`；edge=0.65；cluster=0.70。
冻结基准 config_hash：`{d1.EXPECTED['config_hash']}`；mapping_digest：`{d1.EXPECTED['mapping_digest']}`。
before==after：{freeze['before_equals_after']}；production/config/docs/既有脚本变更：{freeze['protected_file_changes']}；原始告警文件未变：{freeze['original_sources_unchanged']}。
config_hash 是算法+来源部署快照的摘要，不要求8场景互相相同。冻结基准使用已接受 russellmitchell 声明；每场景实际 hash / 完整有效映射与来源快照见 effective_config_snapshots.json。仅既有 namespace/timezone 声明不同，所有算法参数、候选、评分、去重、聚类、方向和映射都与冻结 recipe 一致。

扫描规则在结果前写入 search_plan.json（digest `{content_digest(plan)}`）：15分钟 stride、20–2500条 raw，每场景/尺度最多两个字段覆盖/双源平衡提名，缺双源时取剩余时间中位窗口。另按用户指定重放 Wilson，并从同一起点扩展到4小时。窗口连续、保留两源所有原始告警和重复导入，不拼接、不删除无关联记录。临时切片、完整候选分数数组和 worker 文件结束后删除。
每窗口单 subprocess，180秒上限，并发1；正式候选预算完全不变。可复核连续切片 raw_count、input_alert_ids_digest、dataset_digest、config_hash、formal_result_digest 和源 SHA256。算法重算每个窗口的去重/实体/频率，不复用会改变窗口频率语义的全场景缓存。
8h 仅在已发布条件（已知4h窗口有>=0.68正式边且资源允许）成立时执行；实际尺度见下表。分析结束后再生成此解释，没有标签倒选窗口。

## Q1. 搜描哪些 scenario？

{scenes}

## Q2. 哪些时间尺度？Q3. 分析多少 window？

尝试 {s['windows_attempted']}，完成 {s['windows_evaluated']}，未完成/资源受限 {s['resource_limited_windows']}。

{scale_rows}

## Q4. score distribution？Q5. 各cutoff多少？

总体量化 `{s['pooled_score_distribution']}`。精确线性插值 P90/P95/P99；空候选窗口为 null，不填0。
总体 scored pairs={s['scored_pair_count']}；admitted={s['candidate_pair_count']}。
分布单位：每个代表候选的最高有效完整成员pair；无有效pair时统计最高被拒成员pair。所有分数用未舍入值。**高于0.70的被拒pair不是正式边，也不进入聚类。**
窗口重叠会重复计算相同pair，故另报跨窗口唯一正式edge与Incident身份，不将窗口计数当独立样本量。

{dist}

## Q6. 最高分pair？Q7. 为什么有这个分数？

{highest_text}

{pair_text}
{score_explanation}

## Q8. 正式边多少？Q9. multi-alert Incident多少？

正式边窗口计数 {s['formal_edges']}；跨窗口唯一 edge_id {s['unique_formal_edges']}；cluster-eligible窗口计数 {s['cluster_eligible_edges']}。
multi-fact Incident 窗口计数 {s['multi_alert_incidents']}；跨窗口唯一Incident {s['unique_multi_alert_incidents']}。
multi-fact 要求至少两个去重代表，避免将一个 duplicate group 的多个raw成员当作关联正例；raw multi-alert 数也逐窗口保存。

## Q10. 0.65–0.70 gap 的主要原因？

{gap_reason}
同主机/账号上下文能形成无向关联，但不是显式传播。relation mapping为空时不称 parent-child/pivot/session flow，不用 ATT&CK/类别补关系。强证据个数是冻结 fact/family gate 的口径，不等于独立来源个数。
扩大窗口还会改变 N/df、hot/rarity和候选竞争；因此较大窗口不必然有更高分，不能把分数改变归为调参或只看新告警数。

{graph_rows}

已知窗口逐尺度复现比较（旧阶段结果仅用于比对，本次均实际运行）：

{comparison}

## Q11. 是否有清楚的Demo候选？Q12. 最推荐哪个？Q13. 告警量？Q14. 哪些正式边？Q15. 真正形成Incident？

{best_text}
{'当前仅能展示真实无向关联、字段证据与阈值拒绝原因；缺少满足完整 Demo 要求的 multi-fact Incident，也无依据承诺有方向攻击链。' if not s['multi_alert_incidents'] else '已产生符合冻结聚类保护的 multi-fact Incident；有方向链能力须按真实传播证据单独说明，不能由Incident自动推定。'}
推荐候选的全部正式pair、图结构、频率快照、Incident成员与保护诊断见 positive_windows.json / top_pairs.json。D.1未复制/重构data/demo、未发布Demo manifest、未修改API/frontend/demo.py。

## Q16. 每条边证据可回溯？Q17. 算法或实现异常？

正式生产 grounding 所有完成窗口通过：{s['checks']['grounding_all_complete']}。独立导出审计：{checks['checks']}，issues={checks['issues']}。
检查 raw fingerprint、绑定指针、support pair、唯一fact key/家族、已消耗维度不重复奖励、source unknown/same-origin零奖励、metadata-only/hot-primary禁止、非精确重复正式pair、edge唯一身份、Incident成员不重叠。原始告警附带full_log仅作设备告警内容保存，不额外检测/证据扩展。
同主机登录与session打开是同一Wazuh产生的两条不同原始记录，可能是同一次登录的不同侧面；本报告只陈述记录和共同字段，不声称两个攻击阶段或独立安全设备确认。官方 duplicate/same-observation 和 metadata/local-endpoint/repeated-signature/role-direction边界由既有回归覆盖；没有修改这些冻结判定。
总体最高分是否接受已显式披露，未以高分数量直接声称好结果。未发现可证实的实现异常；有限扫描和测试并非所有实现的穷尽证明。

## Q18. Frozen v4 完全不变？

{freeze}。算法实现文件逐项对照既有 FREEZE_MANIFEST，另对backend/app/configs/docs/frontend/src/AGENTS/已有scripts做before/after内容摘要检查；三份原始需求未变。无阈值/weight/hack/refactor。

## Q19. 是否进入下一步Demo数据冻结？Q20. 最终D.1状态？

`{s['final_recommendation']}`；`{s['status']}`。
{'可以考虑下一Task审核候选，但本Task不冻结数据。' if s['multi_alert_incidents'] else '在此次bounded完成窗口内，当前AIT-ADS告警缺少达到冻结聚类强度的自然正式关联证据，完整Demo输入门槛未满足；这是当前扫描的数据可行性限制，不以边数宣判算法失败。继续寻找真实、更丰富传播/资源/会话字段须另行授权，不能降低阈值制造正例。'}

## 验证与产物

相关回归：{regression}；D.1必要测试：{focused}；Wilson实际两次结果：{s['known_replay']}。
Tests覆盖冻结摘要、连续半开区间含重复、确定性提名、真实重放完整结果一致、未舍入正式阈值、正式聚类拒绝/grounding、GT运行时tripwire和原始证据指针。
仓库检查结果见repository_check.json。前端未修改，本Task未启动UI/AI/独立Evaluation benchmark。
主要产物：本报告、scan_summary.json（所有窗口完整统计/图/正式边）、positive_windows.json（推荐候选/频率）、top_pairs.json（每窗口Top20及全部正式pair）、search_plan.json、effective_config_snapshots.json、freeze_before/after.json、correctness_audit.json、测试XML/日志。
首次扫描命令：`.venv/Scripts/python.exe scripts/d1_positive_scan.py scan`；完成目录有覆盖保护，不能覆盖现有收据。独立重放可导入同一诊断脚本，仅设置输出目录：`.venv/Scripts/python.exe -c "from pathlib import Path; import sys; sys.path.insert(0,'scripts'); import d1_positive_scan as d; d.OUT=Path('outputs/d1_positive_scan_replay').resolve(); d.scan()"`。该命令不改变生产输入或算法配置，本Task已实际完成的两次已知窗口重放见收据。
新增诊断文件：scripts/d1_positive_scan.py、scripts/report_d1_positive_scan.py、backend/tests/test_d1_positive_scan.py；其余新增均位于outputs/d1_positive_scan。没有更改已有生产代码或配置。完成D.1后停止。
"""
    (out/'D1_POSITIVE_FEASIBILITY_REPORT.md').write_text(report,encoding='utf8')
    d1.atomic_json(out/'delivery_receipt.json',dict(status=s['status'],recommendation=s['final_recommendation'],
        best_positive_window=best,best_pair=selected_pair,regression_tests=regression,d1_tests=focused,
        report_sha256=d1.file_digest(out/'D1_POSITIVE_FEASIBILITY_REPORT.md'),correctness_audit=checks['passed']))
    print(json.dumps({'status':s['status'],'formal_edges':s['formal_edges'],'unique_edges':s['unique_formal_edges'],
        'multi_alert_incidents':s['multi_alert_incidents'],'report':'outputs/d1_positive_scan/D1_POSITIVE_FEASIBILITY_REPORT.md'}))


if __name__=='__main__':
    main()
