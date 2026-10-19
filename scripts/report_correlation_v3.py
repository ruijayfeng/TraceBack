"""Production receipt comparison and detailed v3 diagnostics, without labels."""

from collections import Counter, defaultdict
import csv
import json
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def records(path):
    with Path(path).open(encoding='utf-8') as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def save(path,value):
    Path(path).write_text(json.dumps(value,ensure_ascii=False,indent=2,sort_keys=True)+'\n',encoding='utf-8')


def csv_rows(path,rows,fields):
    with Path(path).open('w',encoding='utf-8',newline='') as handle:
        writer=csv.DictWriter(handle,fieldnames=fields);writer.writeheader();writer.writerows(rows)


def run(root=ROOT):
    root=Path(root);out=root/'outputs/correlation_v3'
    receipt=read(out/'REAL_DATA_RESULT.json')
    old=read(root/'outputs/correlation_quality_audit/audit_summary.json')
    new=read(out/'quality_audit/audit_summary.json')
    domain=root/'data/processed'/receipt['analysis_id'];details=root/'outputs/analyses'/receipt['analysis_id']
    old_domain=root/'data/processed'/old['analysis_id']
    alerts={a['alert_id']:a for a in records(domain/'alerts.jsonl')}
    groups=list(records(domain/'dedupe_groups.jsonl'));edges=list(records(domain/'correlation_edges.jsonl'))
    old_edges=list(records(old_domain/'correlation_edges.jsonl'))
    owner={aid:aid for aid in alerts}
    for group in groups:
        owner.update({aid:group['representative_alert_id'] for aid in group['alert_ids']})
    old_ids={e['edge_id'] for e in old_edges};new_ids={e['edge_id'] for e in edges}
    comparison=dict(v2_total_edges=len(old_ids),v3_total_edges=len(new_ids),
        retained_edges=len(old_ids&new_ids),removed_edges=len(old_ids-new_ids),new_edges=len(new_ids-old_ids),
        edge_comparison_basis='Stable CorrelationEdge ID / unordered representative alert pair; changed representative IDs are disclosed separately',
        v2_edges_now_within_same_observation_group=sum(owner[e['source_alert_id']]==owner[e['target_alert_id']] for e in old_edges),
        old_analysis_id=old['analysis_id'],new_analysis_id=new['analysis_id'])
    for field,key in (('near_threshold_ratio','near_threshold_ratio'),('hub_related','hub_edge_count'),
                      ('cross_source','cross_source_edges')):
        comparison['v2_'+field]=old[key];comparison['v3_'+field]=new[key]
    for field in ('weak','suspicious'):
        comparison['v2_'+field+'_ratio']=old['classification'][field]['ratio']
        comparison['v3_'+field+'_ratio']=new['classification'][field]['ratio']
    for prefix,data in (('v2',old),('v3',new)):
        comparison[prefix+'_duplicate_observation_proxy']=data['proxy_counts'].get('repeated_observation_inflation',0)
        comparison[prefix+'_multi_rep_incidents']=data['incidents']['multi_representative']
        comparison[prefix+'_same_rule_clique_components']=data['components']['same_rule_near_clique_count']
        comparison[prefix+'_classification']=data['classification']
    save(out/'V2_V3_COMPARISON.json',comparison)
    family=Counter();network=Counter();reliability={};metadata=[]
    for edge in edges:
        ev=edge['score_breakdown']['evidence_v2']
        assert ev['version']=='v3' and ev['primary_evidence'] and not ev['duplicate_observation_risk'] and not ev['metadata_dominated']
        assert sum(f['family']=='RULE_METADATA' for f in ev['evidence']) <= 1
        if ev['network_continuity_valid']:
            aa=[alerts[edge['support_pair'][f]] for f in ('alert_id_src','alert_id_dst')]
            assert all(a['src_ip'] and a['dst_ip'] and a['src_ip']!=a['dst_ip'] for a in aa)
            assert aa[0]['timestamp'] != aa[1]['timestamp']
            flow_ids={eid for f in ev['evidence'] if f['family']=='NETWORK_FLOW' for eid in f['entity_ids']}
            entity_ids={eid for f in ev['evidence'] if f['dimension'].startswith('entity.') for eid in f['entity_ids']}
            assert not flow_ids & entity_ids
        for fact in ev['evidence']:
            family[(fact['family'],fact['role'])]+=1
        network[('accepted_edge',ev['network_diagnostic'],ev['network_continuity_valid'])]+=1
        for row in ev['entity_reliability']:
            eid=row['entity_id'];r=reliability.setdefault(eid,{**row,'edge_count':0})
            r['edge_count']+=1
        metadata.append(dict(edge_id=edge['edge_id'],metadata_dominated=ev['metadata_dominated'],
                             metadata_fact_count=sum(f['family']=='RULE_METADATA' for f in ev['evidence'])))
    csv_rows(out/'evidence_family_statistics.csv',[dict(family=f,role=r,accepted_fact_count=c) for (f,r),c in sorted(family.items())],
             ['family','role','accepted_fact_count'])
    csv_rows(out/'entity_reliability_statistics.csv',sorted(reliability.values(),key=lambda r:r['entity_id']),
             ['entity_id','frequency','population','rarity','reliability','role_factor','descriptor_factor','hot','edge_count'])
    csv_rows(out/'metadata_dominated_edges.csv',metadata,['edge_id','metadata_dominated','metadata_fact_count'])
    with (out/'v3_edge_samples.jsonl').open('w',encoding='utf-8') as handle:
        for row in records(out/'quality_audit/manual_review_samples.jsonl'):
            handle.write(json.dumps(row,ensure_ascii=False,sort_keys=True)+'\n')
    counts=Counter();cross=Counter();cross_gaps=[];members=0;started=time.monotonic()
    with (details/'diagnostics.jsonl').open('rb') as handle:
        for line in handle:
            if b'"stage":"member_score"' not in line:
                continue
            row=json.loads(line);ev=row['evidence']['evidence_v2'];members+=1
            counts[(ev['decision'],ev['gate_reason'])]+=1
            network[('member_score',ev['network_diagnostic'],ev['network_continuity_valid'])]+=1
            left,right=(alerts[a] for a in row['support_pair'])
            if left['source_namespace']!=right['source_namespace']:
                cross[(ev['decision'],ev['gate_reason'],ev['network_diagnostic'])]+=1
                cross_gaps.append(row['evidence']['gap_seconds'])
            if members%100000==0:
                print(f'v3 diagnostics member_scores={members} elapsed={time.monotonic()-started:.1f}s',flush=True)
    assert members==new['diagnostics']['member_scores']
    csv_rows(out/'network_continuity_statistics.csv',[dict(population=p,diagnostic=d,valid=v,count=c) for (p,d,v),c in sorted(network.items())],
             ['population','diagnostic','valid','count'])
    csv_rows(out/'candidate_evidence_diagnostics.csv',[dict(decision=d,gate_reason=r,member_count=c) for (d,r),c in sorted(counts.items())],
             ['decision','gate_reason','member_count'])
    dup=[dict(metric='dedupe_group_count',v2=9,v3=len(groups)),dict(metric='grouped_alert_count',v2=18,v3=sum(len(g['alert_ids']) for g in groups)),
         dict(metric='representative_count',v2=old['representative_alerts'],v3=new['representative_alerts']),
         dict(metric='repeated_observation_proxy_edges',v2=comparison['v2_duplicate_observation_proxy'],v3=comparison['v3_duplicate_observation_proxy']),
         dict(metric='old_edges_now_within_observation_group',v2=0,v3=comparison['v2_edges_now_within_same_observation_group'])]
    csv_rows(out/'duplicate_observation_statistics.csv',dup,['metric','v2','v3'])
    cross_result=dict(cross_namespace_edges=new['cross_source_edges'],
        candidate_decisions=[r for r in new['diagnostics']['source_candidate_decisions'] if len(set(r['source_pair'].split(' ↔ ')))>1],
        member_diagnostics=[dict(decision=d,gate_reason=g,network_diagnostic=n,count=c) for (d,g,n),c in sorted(cross.items())],
        scored_member_count=sum(cross.values()),minimum_gap_seconds=min(cross_gaps,default=None),maximum_gap_seconds=max(cross_gaps,default=None),
        explanation='Cross pairs were scored. Source names do not attest independence. Vendor rule strings are namespace-scoped; endpoint equality supplies no primary flow without ordering and direction context. Host/account scopes are retained from confirmed deployment declarations. No pair GT identifies missed cross-source attacks.')
    save(out/'CROSS_SOURCE_DIAGNOSTIC.json',cross_result)
    if not edges:
        # Empty denominators stay null; removing known proxy inflation does
        # not measure a zero suspicious ratio or prove recall/precision.
        status='QUALITY_IMPROVED_BUT_DATASET_LIMITED'
    elif new['audit_result']=='OVER_CORRELATED':
        status='STILL_OVER_CORRELATED'
    elif (comparison['v3_duplicate_observation_proxy']<comparison['v2_duplicate_observation_proxy']
            and new['classification']['suspicious']['ratio']<old['classification']['suspicious']['ratio']):
        status='QUALITY_IMPROVED_BUT_DATASET_LIMITED'
    else:
        status='NO_MEANINGFUL_CHANGE'
    result=dict(status=status,audit_result=new['audit_result'],quality_grade=new['quality_grade'],
        dataset_limit_diagnostic='DATASET_HAS_LIMITED_CORRELATABLE_SECURITY_EVENTS' if len(edges)<1000 else None,
        offline_pair_ground_truth='evaluation_not_computable',comparison=comparison,cross_source=cross_result,
        primary_requirement_verified=True,duplicate_only_accepted_edges=0,metadata_dominated_accepted_edges=0,
        accepted_invalid_network_continuity=0,member_diagnostics_count=members)
    result['empty_edge_population']=not edges
    result['suspicious_ratio_improvement_status']='not_applicable_empty_population' if not edges else 'observable_proxy_only'
    result['near_threshold_improvement_status']='not_applicable_empty_population' if not edges else 'see_distribution_no_calibration_claim'
    result['quality_targets']={
        'A_duplicate_proxy':{'v2':comparison['v2_duplicate_observation_proxy'],'v3':comparison['v3_duplicate_observation_proxy']},
        'B_self_flow_proxy':{'v2':old['proxy_counts'].get('network_continuity_same_endpoint',0),'v3':new['proxy_counts'].get('network_continuity_same_endpoint',0)},
        'C_metadata_fact_count':'at most one supporting RULE_METADATA fact per accepted edge, asserted',
        'D_same_rule_cliques':{'v2':comparison['v2_same_rule_clique_components'],'v3':comparison['v3_same_rule_clique_components']},
        'E_suspicious_ratio':{'v2':comparison['v2_suspicious_ratio'],'v3':comparison['v3_suspicious_ratio']},
        'F_near_threshold':{'v2':comparison['v2_near_threshold_ratio'],'v3':comparison['v3_near_threshold_ratio'],
            'ratio_reduced':new['near_threshold_ratio']<old['near_threshold_ratio'] if new['near_threshold_ratio'] is not None else None,
            'independent_primary_contract_verified':True},
        'G_explainability':'all accepted evidence facts and reliability are model validated and traceable; no claim of pair truth'}
    entities={e['entity_id']:e for e in records(domain/'entities.jsonl')}
    result['remaining_resource_context_risks']={
        'url_primary_edges':sum(any(f['family']=='RESOURCE_CONTEXT' and f['role']=='primary'
            and any(entities[e]['type']=='URL' for e in f['entity_ids'])
            for f in edge['score_breakdown']['evidence_v2']['evidence']) for edge in edges),
        'root_path_primary_edges':sum(any(f['role']=='primary' and any(
            entities[e]['type']=='URL' and entities[e]['value']=='/' for e in f['entity_ids'])
            for f in edge['score_breakdown']['evidence_v2']['evidence']) for edge in edges),
        'limitation':'Corpus rarity does not prove semantic specificity. Relative URL paths, including root paths, lack resource authority/target disambiguation and can still form small cliques; no policy or parameters were changed after this audit.'}
    save(out/'RESULT.json',result)
    write_report(out,receipt,old,new,result)
    print(json.dumps(dict(status=status,total_edges=len(edges),classification=new['classification'],counts=receipt['counts']),ensure_ascii=False),flush=True)


def write_report(out,receipt,old,new,result):
    c=receipt['counts'];comparison=result['comparison'];validation=read(out/'validation.json')
    integrity=read(out/'snapshot_integrity.json') if (out/'snapshot_integrity.json').exists() else {'status':'pending final verification'}
    integrity={k:v for k,v in integrity.items() if k!='files'}
    changed=list(read(out/'implementation_freeze.json')['production']) + ['scripts/check_repository.py',
        'scripts/verify_correlation_v3.py','scripts/report_correlation_v3.py','backend/tests/test_correlation_v3.py',
        'evaluation/tests/test_task_06_6.py','evaluation/framework/correlation_quality_audit/cli.py',
        'evaluation/framework/correlation_quality_audit/correlation_run.py']
    sections=[
        ('Files Changed','本专项修改/新增以下文件；工程七份基线、聚类、链算法及历史配置未改。\n\n'+'\n'.join('- `'+p+'`' for p in changed)+'\n\n新产物位于 `outputs/correlation_v3/`；完整 SHA256 清单见 artifact_manifest.json。'),
        ('Root Causes Fixed','v2 的 Wazuh payload 映射只覆盖有 URL 的结构化请求，Dovecot 消息没有 payload fingerprint；不同 native ID/location 的同一次消息未归并。entity IP equality 又用于 topology continuity；同 detector 的 rule/signature/type/category 重复提供语义支持。修复读取已有告警字段，不检索或解析运行日志。'),
        ('Observation / Dedupe Repair',f"去重组 9 → {c['dedupe_group_count']}，组内原告警 18 → {c['grouped_alert_count']}，代表 45,501 → {c['representative_count']}。底层消息 SHA256 + scoped target + ≤2秒 + 至少一项 account/session/完整 network tuple/process instance/resource 相等且无已知矛盾；complete-link 全跨组核验不变。AMiner 多消息 aggregate 不选取单行作事件身份。旧边中 {comparison['v2_edges_now_within_same_observation_group']} 条现在位于同一去重组。全部 45,510 CanonicalAlert 保留。"),
        ('Evidence Independence','实体事实、真实 flow、时间、检测元数据、来源和已核验关系分别记录 family/fact_key/角色/告警内指针。每种实体只取最强独立事实；flow 使用过的 IP、关系使用过的实体不再作为独立实体分。所有正式边具有非空 primary_evidence、唯一 fact_key 与完整可重算 breakdown。新审计存入既有 evidence_v2 兼容槽，version=v3，旧 v2 对象保持原序列化。'),
        ('Network Continuity Repair',f"v2 同本机端点连续性代理 14,532 → {new['proxy_counts'].get('network_continuity_same_endpoint',0)}。任一端 src==dst 明确为 local_host_observation，flow 强度为0；只有严格时间顺序、两个完整非本机流、同 scope dst→src 与端口/已映射行为上下文才能计 flow。只有 equality 不够，也不建立 AlertRelation/ChainEdge。详见 network_continuity_statistics.csv，全成员核验 {result['member_diagnostics_count']} 对。"),
        ('Entity Reliability','df 按去重组、在冻结 frequency_snapshot 上计算。N_eff=max(N,100)，r=max(0.1,log((N_eff+1)/(df+1))/log(N_eff+1))；reliability=(0.1+0.9r)×role×descriptor，有界且严格重算。100 是小 Analysis 的配置先验，不是数据集常量；高频实体保留非零支持，但不能靠频繁上下文独立过 gate。参数未由 GT 校准。'),
        ('Metadata Reliability','rule/signature/type/category 合并为唯一 RULE_METADATA supporting 事实，强度最高0.2，家族权重0.04；无主证据时明确 metadata_dominated_candidate。已观测不同 detector/类别只能辅助确认 HOST/ACCOUNT 的差异上下文，不能自行创建主证据或跨源等价。metadata_dominated_edges.csv 为实际正式边，拒绝候选另在 candidate_evidence_diagnostics.csv 统计。'),
        ('Score / Acceptance Changes','阈值0.65、time权重0.2、entity0.3、source0.1保留；behavior0.2→0.04，relation0.2→0.36，针对检测元数据与核验关系的差别调整，没有统一缩放。沿用 quality/mass 与原惩罚，必须同时有独立 primary、非重复-only 且无 hard guard。缺失、单侧不可观测与已知不匹配分别记录；无证据不视为匹配。未加入degree cap，候选Top-K/预算不改；候选减少来自代表归并，每对保留已有通道 provenance/candidate_reasons。'),
        ('Real russellmitchell Result','正式全量真实分析：`'+receipt['analysis_id']+'`。\n\n```json\n'+json.dumps(c,ensure_ascii=False,indent=2)+'\n```\n\n运行成本：\n\n```json\n'+json.dumps({'runtime':receipt['runtime'],'peak_memory_mb':receipt['peak_memory_mb']},indent=2)+'\n```\n\nProduction GT/AI 均未使用。'),
        ('v2 vs v3 Comparison','ID 口径是 Stable CorrelationEdge ID / representative unordered pair。归并导致的端点变化另计组内旧边数，不冒充 retained。\n\n| metric | v2 | v3 |\n| --- | --- | --- |\n'+'\n'.join(f'| {k} | {comparison["v2_"+k]} | {comparison["v3_"+k]} |' for k in ('total_edges','near_threshold_ratio','weak_ratio','suspicious_ratio','duplicate_observation_proxy','hub_related','cross_source','multi_rep_incidents','same_rule_clique_components'))+f"\n\nRetained {comparison['retained_edges']}；Removed {comparison['removed_edges']}；New {comparison['new_edges']}。全部明细见 V2_V3_COMPARISON.json。"),
        ('Cross-source Result','真实诊断见 CROSS_SOURCE_DIAGNOSTIC.json：\n\n```json\n'+json.dumps(result['cross_source'],ensure_ascii=False,indent=2)+'\n```\n\n没有按跨源数量加奖励。正例 fixture 使用已声明共享 scope 的真实结构化 flow；该 fixture 不冒充本数据集结果。'),
        ('Incident Result','聚类保护、0.70阈值、两桥、Target Set、singleton和链重构代码均保持原样。\n\n```json\n'+json.dumps(new['incidents'],indent=2)+'\n```\n\n多告警 Incident 包含去重展开；multi-representative 才反映不同代表的关联组织价值。全部原始成员一告警一 Incident，ChainEdge=0 时不补造步骤。'),
        ('Correlation Quality Audit Result',f"复用原 audit v1 的 classify、grade、图风险代理、分箱、seed=42 和采样规则，只增加 receipt/destination/version 兼容。等级 {new['quality_grade']}，结果 {new['audit_result']}。\n\n```json\n"+json.dumps(new['classification'],indent=2)+'\n```\n\n审计指标是风险代理，不是 pair TP/FP。改善不能等同于真实 Precision/Recall 提升。'+('正式边为空，B只是原评级公式的默认分支，不代表可信度已获证明；Suspicious比例与near-threshold比例分母为空，均为null，验收E/F不可测，不能称其比例降为0。' if result['empty_edge_population'] else '')+'原审计报告见 quality_audit/CORRELATION_EDGE_QUALITY_AUDIT.md。'),
        ('Tests','新增24项核心测试覆盖20类指定问题及跨detector scope/aggregate/多共享IP引用闭合边界，已有完整成员评分回归也已运行。全部已有 pytest 已实际运行，4项原opt-in重放明确 skipped，未删除失败测试；冻结检查通过精确 v3 前驱链承接授权，旧收据不改。\n\n```json\n'+json.dumps(validation,ensure_ascii=False,indent=2)+'\n```'),
        ('Snapshot Integrity','新的 analysis 与 deterministic snapshot identity 分开记录。历史全部快照、v2 审计/收据、原始输入/标签/映射以及工程七文档逐文件检查；只允许 implementation_freeze 中列明的当前生产实现升级。三次中断验证运行已标 failed，不计正式结果，见 INTERRUPTED_RUNS.json。\n\n```json\n'+json.dumps(integrity,ensure_ascii=False,indent=2)+'\n```\n\n最终 v3 身份：`'+receipt['snapshot_identity']+'`。'),
        ('Remaining Limitations','Offline pair GT 仍不可计算，labels 只有攻击时间窗口，不推导 pair 真值。可证明代理膨胀和伪 flow 减少，不能证明没有漏关联、攻击阶段完整或跨源攻击召回。ObservationIdentity 依赖现有 message/上下文字段，缺失或 aggregate 保守留为独立告警；没有 raw log expansion。参数是未校准假设，不追求保留18,159边。'+(' '+result['dataset_limit_diagnostic'] if result['dataset_limit_diagnostic'] else '')+'；剩余少量边仍须SOC复核。')]
    sections[12] = (sections[12][0], sections[12][1] +
        '\n\n验收目标 A–G 的实际结果：\n\n```json\n' +
        json.dumps(result['quality_targets'], ensure_ascii=False, indent=2) + '\n```\n\n' +
        ('Near-threshold 比例没有降低，不能称目标 F 全面达成；Weak 比例也没有降低。主证据结构可核验，但剩余边的攻击关系质量尚未被证明。'
         if new['near_threshold_ratio'] is not None and new['near_threshold_ratio'] >= old['near_threshold_ratio'] else ''))
    if 'remaining_resource_context_risks' in result:
        sections[15] = (sections[15][0], sections[15][1] +
            '\n\n剩余具体限制：语料中相对稀有不等于语义具体。相对 URL 路径缺少 authority/目标区分，根路径也可能符合当前 rarity gate，仍能形成小型 clique。已据实际样本记录风险，未在审计后按边数修改参数。\n\n```json\n' +
            json.dumps(result['remaining_resource_context_risks'], ensure_ascii=False, indent=2) + '\n```')
    text='# Correlation v3 — Evidence Quality Repair\n\n'
    text+='\n\n'.join('## '+str(i)+'. '+title+'\n\n'+body for i,(title,body) in enumerate(sections,1))
    text+='\n\nCORRELATION_V3_RESULT='+result['status']+'\n'
    (out/'CORRELATION_V3_REPORT.md').write_text(text,encoding='utf-8')


if __name__=='__main__':
    run()
