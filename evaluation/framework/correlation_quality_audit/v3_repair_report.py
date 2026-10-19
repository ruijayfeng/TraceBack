"""Auditable v2/v3 comparison for an explicitly named new production receipt."""

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
import duckdb

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'backend'))
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT))
from app.adapters.base import AdapterSettings
from app.correlation.index import AlertIndex
from app.correlation.scoring import CorrelationScorer
from app.models import CanonicalAlert, DedupeGroup, Entity
from app.services.storage import restore_config
from evaluation.framework.correlation_quality_audit.correlation_quality import digest, effective_contributions
from report_correlation_v3 import read, records, save, csv_rows


REQUIRED = ['CORRELATION_V3_REPORT.md', 'V2_V3_COMPARISON.json', 'evidence_family_statistics.csv',
    'duplicate_observation_statistics.csv', 'network_continuity_statistics.csv',
    'entity_reliability_statistics.csv', 'metadata_dominated_edges.csv', 'v3_edge_samples.jsonl']


def ratio(n, total):
    return n / total if total else None


def metadata_dominated(edge):
    families, _, _ = effective_contributions(edge)
    total = sum(families.values())
    return total > 0 and families['behavior'] >= total * .5


def metrics(summary, edges):
    total = len(edges)
    proxy = summary['proxy_counts']
    counts = dict(total_edges=total, near_threshold_edges=proxy.get('near_threshold', 0),
        weak_evidence_edges=summary['classification']['weak']['count'],
        suspicious_edges=summary['classification']['suspicious']['count'],
        duplicate_observation_proxy=proxy.get('repeated_observation_inflation', 0),
        invalid_network_continuity_proxy=proxy.get('network_continuity_same_endpoint', 0),
        high_frequency_entity_edges=proxy.get('high_frequency_entity_exposure', 0),
        hub_related_edges=summary['hub_edge_count'],
        metadata_dominated_edges=sum(metadata_dominated(e) for e in edges),
        cross_source_edges=summary['cross_source_edges'],
        multi_representative_incidents=summary['incidents']['multi_representative'],
        chain_edges=summary['incidents']['chain_edges'])
    for name in ('near_threshold', 'weak_evidence', 'suspicious', 'duplicate_observation',
                 'invalid_network_continuity', 'high_frequency_entity', 'hub_related', 'metadata_dominated'):
        field = name + '_edges' if name not in ('duplicate_observation', 'invalid_network_continuity') else name + '_proxy'
        counts[name + '_ratio'] = ratio(counts[field], total)
    return counts


def diagnostic_records(details, bounded):
    if not bounded:
        yield from records(details/'diagnostics.jsonl')
        return
    db=duckdb.connect(':memory:')
    try:
        for part in sorted((details/'candidate_decisions').glob('*.parquet')):
            cursor=db.execute("SELECT source_id,target_id,decision,rule_id,evidence_decision,score,edge_id FROM read_parquet('"+str(part).replace("'","''")+"')")
            while batch:=cursor.fetchmany(256):
                for a,b,decision,reason,evidence,score,edge in batch:
                    yield dict(stage='correlation_decision',support_key=[a,b],decision=decision,
                        rule_id=reason,evidence_decision=evidence,score=score,edge_id=edge)
        for part in sorted((details/'candidate_samples').glob('*.parquet')):
            cursor=db.execute("SELECT payload FROM read_parquet('"+str(part).replace("'","''")+"')")
            while batch:=cursor.fetchmany(256):
                for (payload,) in batch:
                    yield json.loads(payload)['member']
    finally:
        db.close()


def run(out):
    out = Path(out).resolve()
    if not out.is_relative_to(ROOT / 'outputs'):
        raise ValueError('output_scope')
    if (out / 'CORRELATION_V3_REPORT.md').exists():
        raise ValueError('report_exists_do_not_overwrite')
    receipt = read(out / 'REAL_DATA_RESULT.json')
    assert receipt['status'] == 'completed' and receipt['is_complete'] and not receipt['ground_truth_used']
    before = read(ROOT / 'outputs/correlation_quality_audit/audit_summary.json')
    after = read(out / 'quality_audit/audit_summary.json')
    domain = ROOT / 'data/processed' / receipt['analysis_id']
    details = ROOT / 'outputs/analyses' / receipt['analysis_id']
    bounded=read(details/'bounded_diagnostics.json') if (details/'bounded_diagnostics.json').exists() else None
    old_domain = ROOT / 'data/processed' / before['analysis_id']
    alerts = {a['alert_id']: a for a in records(domain / 'alerts.jsonl')}
    entities = {e['entity_id']: e for e in records(domain / 'entities.jsonl')}
    groups = list(records(domain / 'dedupe_groups.jsonl'))
    edges = list(records(domain / 'correlation_edges.jsonl'))
    old_edges = {e['edge_id']: e for e in records(old_domain / 'correlation_edges.jsonl')}
    new_edges = {e['edge_id']: e for e in edges}
    owner = {a: a for a in alerts}
    for group in groups:
        owner.update({a: group['representative_alert_id'] for a in group['alert_ids']})
    members = defaultdict(list)
    for a, rep in sorted(owner.items()):
        members[rep].append(a)
    record = read(domain / 'analysis.json')
    config = restore_config(record['config_snapshot']['algorithm'])
    settings = {n: AdapterSettings(**v) for n, v in record['config_snapshot']['sources'].items()}
    index = AlertIndex([CanonicalAlert.model_validate(a) for a in alerts.values()],
        [DedupeGroup.model_validate(g) for g in groups], [Entity.model_validate(e) for e in entities.values()])
    assert index.frequency_snapshot() == read(details / 'frequency_snapshot.json')
    scorer = CorrelationScorer(index, config, settings, record['config_hash'])
    old_ids, new_ids = set(old_edges), set(new_edges)
    retained, removed, added = old_ids & new_ids, old_ids - new_ids, new_ids - old_ids
    old_key_to_ids = defaultdict(list)
    removal_reasons = Counter()
    for eid in sorted(removed):
        e = old_edges[eid]
        key = tuple(sorted((owner[e['source_alert_id']], owner[e['target_alert_id']])))
        if key[0] == key[1]:
            removal_reasons['same_observation_dedupe_group'] += 1
        else:
            old_key_to_ids[key].append(eid)
    network = Counter()
    gates = Counter()
    flow_roles = Counter()
    source_decisions = Counter()
    admission = {}
    rejected_samples = {}
    if bounded:
        network.update({('member_score',r['diagnostic'],r['valid']):r['count'] for r in bounded['network_statistics']})
        gates.update({(r['decision'],r['gate_reason']):r['count'] for r in bounded['gate_statistics']})
        flow_roles.update({('member_score',r['diagnostic']):r['count'] for r in bounded['flow_role_statistics']})
        for r in bounded['member_source_decisions']:
            names=r['source_pair'].split(' ↔ ')
            if len(names)==2 and names[0]!=names[1]:
                source_decisions[(r['decision'],r['gate_reason'])]+=r['count']
    old_audit = {r['edge_id']: r for r in records(ROOT / 'outputs/correlation_quality_audit/all_edge_audit.jsonl')}
    # Deterministic manual samples, never part of production scoring.
    selected_removed = set(sorted(removed, key=lambda e: (-old_edges[e]['score'], e))[:8])
    for flag in ('repeated_observation_inflation','hub_endpoint','high_frequency_entity_exposure','network_continuity_same_endpoint'):
        selected_removed.update(sorted(e for e in removed if flag in old_audit[e]['risk_flags'])[:4])
    selected_member_pairs = {tuple(old_edges[e]['support_pair'].values()): e for e in selected_removed}
    seen_decisions = set()
    for row in diagnostic_records(details,bounded):
            if row['stage']=='member_score':
                ev = row['evidence']['evidence_v2']
                if not bounded:
                    network[('member_score', ev['network_diagnostic'], ev['network_continuity_valid'])] += 1
                    gates[(ev['decision'], ev['gate_reason'])] += 1
                a, b = (alerts[x] for x in row['support_pair'])
                same_src = a['src_ip'] is not None and a['src_ip'] == b['src_ip']
                same_dst = a['dst_ip'] is not None and a['dst_ip'] == b['dst_ip']
                if not bounded:
                    flow_roles[('member_score','src_src_only' if same_src and not same_dst else
                    'dst_dst_only' if same_dst and not same_src else 'same_local_endpoint_proxy' if
                    any(x['src_ip'] and x['src_ip']==x['dst_ip'] for x in (a,b)) else 'other')] += 1
                categories = []
                if ev['metadata_dominated']:
                    categories.append('metadata_dominated_rejected')
                if any(r['hot'] for r in ev['entity_reliability']):
                    categories.append('high_frequency_entity_rejected')
                if a['source_namespace'] != b['source_namespace']:
                    categories.append('cross_source_rejected')
                    if not bounded:
                        source_decisions[(ev['decision'],ev['gate_reason'])] += 1
                if 'flow' in ev['network_diagnostic']:
                    categories.append('network_context_rejected' if ev['decision']!='ACCEPT' else 'network_context_accepted')
                for category in categories:
                    if category not in rejected_samples:
                        rejected_samples[category] = row
            elif row['stage']=='correlation_decision':
                key = tuple(row['support_key'])
                if key in old_key_to_ids:
                    seen_decisions.add(key)
                    reason = row.get('evidence_decision', row['rule_id'])
                    if row['decision']=='accept':
                        reason = 'accepted_under_changed_representative_identity'
                    removal_reasons[reason] += len(old_key_to_ids[key])
                    admission.update({e: row for e in old_key_to_ids[key]})
    for key, ids in old_key_to_ids.items():
        if key not in seen_decisions:
            removal_reasons['not_admitted_after_observation_regrouping'] += len(ids)
    assert sum(removal_reasons.values()) == len(removed)
    v2, v3 = metrics(before, list(old_edges.values())), metrics(after, edges)
    comparison = dict(v2_total_edges=len(old_ids), v3_total_edges=len(new_ids),
        retained_edges=len(retained), removed_edges=len(removed), new_edges=len(added),
        v2=v2, v3=v3, removed_reason_counts=dict(sorted(removal_reasons.items())),
        retained_edge_ids=sorted(retained), new_edge_ids=sorted(added),
        comparison_basis='Stable CorrelationEdge ID / unordered representative pair; regrouped identities separately disclosed',
        metadata_dominated_definition='behavior/detector metadata contributes >=50% of positive score, using exact quality/mass family attribution',
        old_analysis_id=before['analysis_id'], new_analysis_id=receipt['analysis_id'],
        prior_v3_analysis_id=read(ROOT/'outputs/correlation_v3/REAL_DATA_RESULT.json')['analysis_id'])
    save(out / 'V2_V3_COMPARISON.json', comparison)
    families = Counter()
    for e in edges:
        ev = e['score_breakdown']['evidence_v2']
        assert ev['primary_evidence'] and not ev['duplicate_observation_risk'] and not ev['metadata_dominated']
        assert len({f['fact_key'] for f in ev['evidence']}) == len(ev['evidence'])
        for fact in ev['evidence']:
            assert set(fact['source_alert_ids']) == set(e['support_pair'].values()) and fact['observation_ids']
            families[(fact['family'],fact['role'])] += 1
        network[('formal_edge',ev['network_diagnostic'],ev['network_continuity_valid'])] += 1
    csv_rows(out/'evidence_family_statistics.csv',
        [dict(population='v3_formal_edges',family=f,role=r,fact_count=c) for (f,r),c in sorted(families.items())]+
        [dict(population=p,family=r['family'],role=r['role'],fact_count=r['count'])
            for p,k in [('v3_all_member_scores','evidence_family_statistics'),('v3_all_candidates','candidate_evidence_family_statistics')]
            for r in (bounded or {}).get(k,[])],['population','family','role','fact_count'])
    csv_rows(out/'network_continuity_statistics.csv',
        [dict(population=p,diagnostic=d,valid=v,count=c) for (p,d,v),c in sorted(network.items())]+
        [dict(population=p,diagnostic=d,valid=False,count=c) for (p,d),c in sorted(flow_roles.items())],
        ['population','diagnostic','valid','count'])
    old_groups=list(records(old_domain/'dedupe_groups.jsonl'))
    def dedupe_stats(gg, population):
        grouped=sum(len(g['alert_ids']) for g in gg)
        distribution=Counter(len(g['alert_ids']) for g in gg)
        singleton=population-grouped
        distribution[1]=singleton
        return dict(canonical_alerts=population,persisted_multi_alert_groups=len(gg),singleton_groups=singleton,
            logical_dedupe_groups=singleton+len(gg),representatives=singleton+len(gg),
            max_group_size=max(distribution,default=0),group_size_distribution=dict(sorted(distribution.items())))
    dedupe = {'v2':dedupe_stats(old_groups,before['total_alerts']),'v3':dedupe_stats(groups,len(alerts))}
    csv_rows(out/'duplicate_observation_statistics.csv',
        [dict(version=version,metric=k,value=json.dumps(value,sort_keys=True)) for version,data in dedupe.items() for k,value in data.items()],
        ['version','metric','value'])
    entity_rows=[]
    for eid,e in sorted(entities.items()):
        rarity=scorer.evidence_evaluator.rarity(eid)
        observations=(bounded or {}).get('entity_reliability_values',{}).get(eid,{})
        rows=[r for edge in edges for r in edge['score_breakdown']['evidence_v2']['entity_reliability'] if r['entity_id']==eid]
        entity_rows.append(dict(entity_id=eid,type=e['type'],value=e['value'],scope=e['scope'],
            representative_frequency=index.df[eid],population=index.N,rarity=rarity,
            base_reliability=config.algorithm.score.evidence_v3.reliability_floor+(1-config.algorithm.score.evidence_v3.reliability_floor)*rarity,
            hot=scorer.evidence_evaluator.hot(eid),formal_edge_count=len(rows),
            effective_reliability_min=min((r['reliability'] for r in rows),default=None),
            effective_reliability_max=max((r['reliability'] for r in rows),default=None),
            all_member_evaluation_count=observations.get('count',0),
            all_member_reliability_min=observations.get('min'),
            all_member_reliability_max=observations.get('max'),
            all_member_reliability_mean=observations.get('sum',0)/observations['count'] if observations.get('count') else None))
    csv_rows(out/'entity_reliability_statistics.csv',entity_rows,list(entity_rows[0]) if entity_rows else ['entity_id'])
    csv_rows(out/'metadata_dominated_edges.csv',
        [dict(version=v,edge_id=e['edge_id'],score=e['score'],metadata_dominated=True,
            family_contributions=json.dumps(effective_contributions(e)[0],sort_keys=True))
         for v,ee in [('v2',list(old_edges.values())),('v3',edges)] for e in ee if metadata_dominated(e)],
        ['version','edge_id','score','metadata_dominated','family_contributions'])
    def describe(e, categories, score=None, decision=None, collapsed=False):
        aa=[alerts[a] for a in e['support_pair'].values()]
        if score is None:
            breakdown=e['score_breakdown']; ev=breakdown['evidence_v2']; actual_score=e['score']
            guards=[]
        else:
            breakdown=scorer.breakdown(score).model_dump(mode='json'); ev=breakdown['evidence_v2']; actual_score=score.score
            guards=score.rejection_codes
        all_alert_ids=sorted({a for endpoint in (e['source_alert_id'],e['target_alert_id']) for a in members[owner[endpoint]]})
        return dict(edge_id=e['edge_id'],sampling_categories=categories,alert_a=aa[0],alert_b=aa[1],
            source_alert_ids=all_alert_ids,source_namespaces=sorted({alerts[a]['source_namespace'] for a in all_alert_ids}),
            score=actual_score,old_score=e['score'] if score else None,score_breakdown=breakdown,
            score_unrounded=actual_score if score else min(1.,max(0.,breakdown['raw_total'])),
            independent_facts=ev.get('evidence',[]),independent_fact_keys=[f['fact_key'] for f in ev.get('evidence',[])],
            evidence_families=ev.get('evidence_families',[]),primary_evidence=ev.get('primary_evidence',[]),
            supporting_evidence=ev.get('supporting_evidence',[]),
            observation_ids=sorted({scorer.duplicate.observation.identities[a['alert_id']].observation_id for a in aa}),
            entity_reliability=ev.get('entity_reliability',[]),guards=guards,gate_reason=ev['gate_reason'],
            decision=decision or ev['decision'],same_observation_group=collapsed,
            admission=admission.get(e['edge_id']),replay_vs_diagnostic='offline member recomputation for removed samples; production admission remains authoritative' if score else 'formal frozen edge')
    sample_rows=[]
    top={e['edge_id'] for e in sorted(edges,key=lambda e:(-e['score_breakdown']['raw_total'],e['edge_id']))[:8]}
    for e in edges:
        categories=[]
        if e['edge_id'] in top: categories.append('highest_score')
        if .65 <= e['score_breakdown']['raw_total'] < .70: categories.append('near_threshold')
        categories.append('retained' if e['edge_id'] in retained else 'new')
        if e['score_breakdown']['evidence_v2']['network_continuity_valid']: categories.append('network_continuity')
        if len({alerts[a]['source_namespace'] for a in e['support_pair'].values()})>1: categories.append('cross_source')
        sample_rows.append(describe(e,categories))
    for eid in sorted(selected_removed):
        e=old_edges[eid]
        pair=scorer.score_pair(*e['support_pair'].values())
        collapsed=owner[e['source_alert_id']]==owner[e['target_alert_id']]
        sample_rows.append(describe(e,['removed_v2',*old_audit[eid]['risk_flags']],pair,
            'REJECT_SAME_OBSERVATION_GROUP' if collapsed else admission.get(eid,{}).get('evidence_decision','NOT_ADMITTED'),collapsed))
    for category,row in sorted(rejected_samples.items()):
        a,b=row['support_pair']
        pair=scorer.score_pair(a,b)
        e=dict(edge_id='diagnostic:'+a+':'+b,source_alert_id=owner[a],target_alert_id=owner[b],
            support_pair=dict(alert_id_src=a,alert_id_dst=b),score=row['score'])
        sample_rows.append(describe(e,[category],pair, row['evidence']['evidence_v2']['decision']))
    with (out/'v3_edge_samples.jsonl').open('w',encoding='utf-8') as handle:
        for row in sample_rows:
            handle.write(json.dumps(row,ensure_ascii=False,sort_keys=True)+'\n')
    save(out/'sample_coverage.json',dict(counts=dict(Counter(c for r in sample_rows for c in r['sampling_categories'])),
        note='Absent formal strata are represented by rejected real candidates when available; no fabricated edges',
        source_candidate_decisions=[dict(decision=d,gate_reason=g,count=n) for (d,g),n in sorted(source_decisions.items())]))
    csv_rows(out/'candidate_evidence_diagnostics.csv',
        [dict(decision=d,gate_reason=g,count=n) for (d,g),n in sorted(gates.items())],['decision','gate_reason','count'])
    save(out/'observation_identity_index.json', {aid:dict(observation_id=x.observation_id,
        identity_basis='network_event' if x.event_fingerprint else 'embedded_message' if x.message_fingerprint else 'unresolved',
        source_namespace=alerts[aid]['source_namespace'],representative_id=owner[aid],
        raw_evidence_pointers=sorted(set(x.pointers+x.event_pointers))) for aid,x in sorted(scorer.duplicate.observation.identities.items())})
    status='STILL_OVER_CORRELATED' if after['audit_result']=='OVER_CORRELATED' else 'QUALITY_IMPROVED_BUT_DATASET_LIMITED'
    if v3['duplicate_observation_proxy'] >= v2['duplicate_observation_proxy'] and v3['invalid_network_continuity_proxy']>=v2['invalid_network_continuity_proxy']:
        status='NO_MEANINGFUL_CHANGE'
    result=dict(status=status,counts=receipt['counts'],comparison=comparison,dedupe=dedupe,
        audit_result=after['audit_result'],quality_grade=after['quality_grade'],sample_count=len(sample_rows),
        valid_directional_continuity=sum(e['score_breakdown']['evidence_v2']['network_continuity_valid'] for e in edges),
        all_formal_edges_have_traceable_independent_primary=True,
        labels_used_in_production=False,offline_pair_ground_truth='unavailable',
        acceptance_note='Risk proxies and factual traceability improved; no claim of attack precision/recall or calibrated probability')
    save(out/'RESULT.json',result)
    validation=read(out/'validation.json')
    integrity=read(out/'snapshot_integrity.json')
    changed={
        'backend/app/config.py':('A/D','版本化 flow 字段指针与弱资源描述质量因子；历史默认不改变旧配置 hash'),
        'configs/algorithm-v3.yaml':('A/C/D','显式配置原始 flow/transaction/protocol/event timestamp；弱资源因子 0.25；阈值保持 0.65'),
        'backend/app/dedup/observation.py':('A','确定性 scope+flow+tuple+protocol+transaction/time 身份，避免仅凭规则或产品名区分事实'),
        'backend/app/dedup/grouping.py':('A','增加 observation 复合索引，继续 complete-link，原告警指针全部保留'),
        'backend/app/correlation/evidence_v3.py':('B/C/D/E','独立 flow 上下文验证、消耗关系使用的实体、弱 URL 降级并记录证据 provenance'),
        'backend/app/correlation/scoring.py':('C','仅核验完整 flow 后消除关联层伪目标软冲突，不修改 hard guard 或传播关系'),
        'backend/app/models/correlation_v3.py':('B','可选 source_alert_ids/observation_ids 严格校验，旧事实序列化省略新字段'),
        'backend/app/models/domain.py':('B','正式事实的 source alerts 必须与唯一 support_pair 闭合'),
        'backend/app/correlation/edges.py':('B','明确实现版本 r2，稳定对象身份规则不变'),
        'backend/app/services/analysis.py':('B','新分析实现版本，已有快照继续只读'),
        'backend/app/services/storage.py':('存储','仅 r2 启用 bounded sink；列式诊断分片 SHA-256 纳入新快照 manifest'),
        'backend/app/services/bounded_diagnostics.py':('存储','256条或8MiB批次；全量精确聚合，压缩 Parquet 决策与限额拒绝样本，不反馈评分'),
        'scripts/check_repository.py':('保护','只列举新增的诊断模块，不扩大业务目录通配权限'),
        'evaluation/framework/correlation_quality_audit/correlation_run.py':('验收','兼容 bounded 聚合计数；classify/质量分层政策原封不动'),
        'evaluation/tests/test_correlation_quality_audit.py':('验收','聚合计数读取不能把审计样本数当作总体'),
        'backend/tests/test_correlation_v3.py':('A–E','保留原回归并增加 flow 重复、transaction、方向、资源质量、provenance 与历史兼容测试'),
        'evaluation/tests/test_task_06_6.py':('保护','通过精确前驱 receipt 承接当前授权，旧 freeze 文件不改'),
        'scripts/verify_correlation_v3.py':('验收','显式新输出目录和新分析目录透明压缩，拒绝覆盖收据'),
        'scripts/report_correlation_v3_repair.py':('验收','调用隔离的离线报告模块，不导入 evaluation 到生产脚本'),
        'evaluation/framework/correlation_quality_audit/v3_repair_report.py':('验收','同审计政策对比、全量统计、删除原因、原始样本、八项产物与报告')}
    sections=[]
    sections.append(('Files Changed','| File | Root Cause | Change / Why |\n| --- | --- | --- |\n'+
        '\n'.join(f'| `{p}` | {cause} | {description} |' for p,(cause,description) in changed.items())))
    sections.append(('Root Causes Fixed',
        'A：同一网络 flow 的不同 signature/规则包装按底层观测归组；transaction 不同保留。B：相同实体只贡献一次，关系与 flow 消耗重叠实体，家族按可观测性计算；supporting 不随字段数量累加。C：src-src、dst-dst、本机 src==dst 不作为连续性；严格时间、有方向端点和独立完整流才可通过。D：冻结组频率、角色、描述质量共同决定可靠性，根路径/无目标相对 URL 不作 primary。E：检测元数据合为一个低权重 supporting 事实，无独立 primary 禁止准入。'))
    sections.append(('Observation / Dedupe Repair','全部 CanonicalAlert 保留；multi-alert group 持久化，singleton 为逻辑组。representative 为最小 alert_id。原始告警、namespace、raw refs 见 observation_identity_index.json 与样本。\n\n```json\n'+json.dumps(dedupe,ensure_ascii=False,indent=2)+'\n```'))
    sections.append(('Evidence Independence','EvidenceFact 包含 fact_key/family/role/entity_ids、绑定 raw EvidencePointer、source_alert_ids 和 observation_ids。已被 primary relation/flow 使用的实体不能再被 entity 家族当独立事实；relation 家族取 max，metadata 家族只有一项。相同 attested observation ID 即使超出去重窗口或存在规范化字段矛盾，也不能充当两个独立事实；新增5秒/30秒多检测器回归覆盖此准入漏洞，保守去重窗口不扩大。缺失维度不进入可观测分母，已知不匹配仍为0。正式边同时满足 primary、mass、threshold 和 hard guards。'))
    sections.append(('Network Continuity Repair',f"旧 invalid continuity proxy={v2['invalid_network_continuity_proxy']}，新={v3['invalid_network_continuity_proxy']}；正式有效 directional continuity={result['valid_directional_continuity']}。完整两个 observation 必须具有 flow ID、全部端口、协议一致、network scope 一致、严格时间顺序与 dst→src 方向；端口或行为上下文仅为额外条件，不能取代完整流。metadata 类别单独相容不再产生 flow 主证据。只修复无向关联上下文，不创建 AlertRelation/ChainEdge。"))
    sections.append(('Entity Reliability','N/df(e) 从去重完成后的本 Analysis frequency_snapshot 冻结；N_eff=max(N,100)，rarity=max(0.1,log((N_eff+1)/(df+1))/log(N_eff+1))；reliability=(0.1+0.9×rarity)×role_factor×descriptor_factor。高频实体继续保留解释，但不能作为 primary。无目标相对 URL、根路径和无 host 的 FILE/COMMAND 使用描述因子0.25；频率低不能替代描述具体性。完整实体统计表覆盖所有实体，不只已接受边。'))
    sections.append(('Metadata Reinforcement Repair','rule/signature/alert_type/category 合并一个 RULE_METADATA supporting 事实，强度上限0.2，家族权重0.04；metadata-only 没有 primary，不得正式入边。正式 metadata-dominated 统计以 exact quality/mass attribution 的正贡献中 metadata≥50% 定义，v2/v3采用同口径；候选无主证据的 metadata domination 另报，不混淆正式边与拒绝候选。'))
    table='| Metric | v2 | v3 |\n| --- | ---: | ---: |\n'+'\n'.join(f'| {k} | {v2[k]} | {v3[k]} |' for k in v2)
    sections.append(('V2 → V3 Comparison',table+f"\n\nRetained={len(retained)}；Removed={len(removed)}；New={len(added)}。删除原因按实际候选决策与去重映射核对：\n\n```json\n"+json.dumps(dict(removal_reasons),ensure_ascii=False,indent=2)+'\n```\n保留边仍有独立主证据并通过同一阈值；新边若存在，按样本中的事实、代表变更和实际准入解释。对象 ID 变化不冒充 retained。'))
    examples=[]
    for category in ('highest_score','near_threshold','removed_v2','metadata_dominated_rejected','high_frequency_entity_rejected','network_context_rejected','cross_source_rejected'):
        sample=next((r for r in sample_rows if category in r['sampling_categories']),None)
        if sample:
            examples.append(f"- {category}：`{sample['alert_a']['alert_id']}` / `{sample['alert_b']['alert_id']}`；score={sample['score']:.6f}；{sample['decision']}，gate={sample['gate_reason']}；primary={sample['primary_evidence']}。完整 raw 和分解见 JSONL。")
    sections.append(('Sample Audit','\n'.join(examples)+f'\n\n共 {len(sample_rows)} 个真实样本；全量类别覆盖见 sample_coverage.json。未出现的正式类别说明为空，使用拒绝候选分析成因，禁止造边补样本。'))
    sections.append(('Correlation / Incident / Chain Result',
        '以下为独立真实 russellmitchell 全量 Analysis Service 结果。Incident clustering / Chain mapping / direction / threshold 未修改。\n\n```json\n'+json.dumps(receipt,ensure_ascii=False,indent=2)+'\n```'))
    sections.append(('Tests','真实执行结果，skip 为仓库现有 opt-in 验收，不将其计为通过。全量真实重放已另行完成。\n\n```json\n'+json.dumps(validation,ensure_ascii=False,indent=2)+'\n```'))
    sections.append(('Snapshot Integrity','逐文件 SHA-256 核对已有快照、原始输入、基线文档、配置、历史报告和旧 freeze 收据；只允许精确列举的当前生产修改。旧 v2/v3 analysis 和报告均未覆盖；新路径为 outputs/correlation_v3/repair_20261010。\n\n```json\n'+json.dumps({k:v for k,v in integrity.items() if k!='files'},ensure_ascii=False,indent=2)+'\n```'))
    storage=storage_inventory(out,domain,details,bounded)
    save(out/'storage_strategy.json',storage)
    sections.append(('Storage / Diagnostic Strategy',
        '原完整 JSONL 方案预计约35 GB（历史 v3 已达26.37 GB，本次部分评分已超过10 GB；属于估算，不是完整回放实测）。按用户调整终止并重跑；仅清理本次未完成运行的大诊断，不删除历史文件。\n\n'
        '候选生成按代表告警处理；全局 top-K 准入保留必要的候选及准入依据索引以维持原排序、预算和结果，评分前将同一有序计划分批写入压缩 Parquet 并释放对象列表。评分流逐对计算、即时聚合，每批最多256条或8MiB；最多保留当前候选的最高有效/最高观测成员诊断，全部候选评分诊断不驻留内存。\n\n'
        '全量精确数据：正式 CorrelationEdge 全部及其完整原始证据；候选/成员评分计数、接受/拒绝、原因、事实家族、重复观测、网络连续性、实体可靠性、metadata domination、未舍入分数桶；v2/v3 retained/removed/new集合及删除决策均精确。轻量最终决策保存为压缩 Parquet，不保存全部中间评分过程。\n\n'
        '仅用于人工审计的拒绝样本：每一实际拒绝原因最多500条；0.60≤score<0.70最多2000条；duplicate/invalid-network/hot-entity/metadata各最多500条。采样按稳定候选顺序取前若干条，有偏，不能据此估算总体比例。样本原始序列化累计达到512MiB即停止增加样本，聚合与评分继续；一般JSON诊断64MiB后转聚合，必要溢出进入列式分片，单文件512MiB guard。大型中间数据采用 ZSTD Parquet；算法、阈值、准入与正式边不受采样影响。\n\n```json\n'+json.dumps(storage,ensure_ascii=False,indent=2)+'\n```'))
    sections.append(('Remaining Limitations',
        f"沿用 audit v1 结果={after['audit_result']}，grade={after['quality_grade']}；代理不是攻击真值。剩余 near-threshold ratio={v3['near_threshold_ratio']}、weak ratio={v3['weak_evidence_ratio']}，两项比例均未下降；正式 metadata-dominated 同口径为0→0，也不能宣称下降。重复观测、无效连续性、高频实体风险代理下降，但尚不能证明剩余边的攻击关联质量。没有 pair 级 ground truth，不能证明 Precision/Recall 或没有漏关联；不能把跨源边为0解释成不存在跨源攻击。AMiner aggregate 仍不能选单条日志当 observation；host/account/session 未声明共享部署 scope，不能跨源猜别名。source 名差异不证明独立。稀有完整 URL/FILE/COMMAND 也不等于已确认攻击；所有正式边仍须SOC复核。模型参数未用 labels 校准。\n\n"
        '数据证据覆盖：9186条告警有 raw flow_id 和完整 canonical 网络四元组，但并不自动构成方向连续性；process instance 为0；14618条含session，但两来源均未声明session_scope，不能把字符串相同当跨源会话证明。完整 baseline 覆盖见 dataset_evidence_coverage.json；新 snapshot 的 CanonicalAlert 字节与baseline一致后才沿用此覆盖统计。'))
    report=('# Correlation v3 — Evidence Quality Repair（r2，全量验收）\n\n'+
        '\n\n'.join(f'## {i}. {title}\n\n{body}' for i,(title,body) in enumerate(sections,1))+
        '\n\nCORRELATION_V3_RESULT='+status+'\n')
    (out/'CORRELATION_V3_REPORT.md').write_text(report,encoding='utf-8')
    assert all((out/p).is_file() for p in REQUIRED)
    save(out/'artifact_manifest.json',dict(analysis_id=receipt['analysis_id'],required_deliverables=REQUIRED,
        files={p.name:dict(sha256=digest(p),bytes=p.stat().st_size) for p in sorted(out.iterdir()) if p.is_file() and p.name!='artifact_manifest.json'},
        audit_policy_sha256=digest(ROOT/'evaluation/framework/correlation_quality_audit/correlation_quality.py')))
    print(json.dumps(dict(status=status,edges=len(edges),retained=len(retained),removed=len(removed),new=len(added),samples=len(sample_rows))),flush=True)


def storage_inventory(out,domain,details,bounded):
    import ctypes,os
    sizes={}
    allocated=0
    restart=read(out/'storage_restart.json')
    aborted=[restart[k] for k in ('aborted_analysis_id','columnar_preparation_restart','taskA_independence_gate_restart') if k in restart]
    bases=[out,domain,details,ROOT/'work/repair_20261010']
    bases.extend(ROOT/folder/aid for aid in aborted for folder in ('data/processed','outputs/analyses'))
    for base in bases:
        for p in base.rglob('*'):
            if not p.is_file():
                continue
            size=p.stat().st_size
            assert size <= 1024**3,('output_size_guard',str(p),size)
            sizes[p.relative_to(ROOT).as_posix()]=size
            physical=size
            if os.name=='nt':
                hi=ctypes.c_ulong()
                f=ctypes.windll.kernel32.GetCompressedFileSizeW
                f.argtypes=[ctypes.c_wchar_p,ctypes.POINTER(ctypes.c_ulong)]
                f.restype=ctypes.c_ulong
                lo=f(str(p.resolve()),ctypes.byref(hi))
                physical=lo+(hi.value<<32)
            allocated+=physical
    return dict(original_estimate=read(out/'storage_restart.json'),logical_bytes=sum(sizes.values()),
        allocated_bytes=allocated,largest_file_bytes=max(sizes.values(),default=0),file_count=len(sizes),
        by_directory={base.relative_to(ROOT).as_posix():sum(v for k,v in sizes.items() if k.startswith(base.relative_to(ROOT).as_posix()+'/')) for base in bases},
        sample_counts=(bounded or {}).get('sample_counts',{}),
        sample_size_guard_triggered=(bounded or {}).get('sample_size_guard_triggered'),
        exact_counts=(bounded or {}).get('counts',{}),
        sample_population='rejected candidate best valid member, or highest observed member if none valid',
        sampling_policy=(bounded or {}).get('policy',{}),all_files_below_1GB=True,
        scope='all analyses created by this repair including unfinished retries, current repair reports and workspace scratch; excludes immutable historical artifacts',
        bytes_note='captured immediately before final report/manifest; final size verification receipt adds exact final totals')


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--destination',required=True)
    args=parser.parse_args()
    run(ROOT/args.destination)
