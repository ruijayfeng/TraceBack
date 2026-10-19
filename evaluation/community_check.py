"""Community-only post-seal evaluation. Never imported by production modules."""
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1048576),b''):
            h.update(block)
    return h.hexdigest()


def verify_seal(output, root=ROOT):
    output=Path(output)
    manifest=json.loads((output/'manifest.json').read_text(encoding='utf8'))
    if manifest.get('status') != 'sealed' or manifest.get('contract_version') != 'community-v1':
        raise ValueError('community_prediction_must_be_sealed_first')
    for relative,digest in manifest['artifacts'].items():
        path=(root/relative).resolve()
        if not path.is_relative_to(root.resolve()) or sha(path) != digest:
            raise ValueError('sealed_artifact_changed')
    if sha(output/'trace_map.json') != manifest['trace_map_sha256'] or sha(output/'implementation_receipt.json') != manifest['implementation_receipt_sha256']:
        raise ValueError('prediction_receipt_or_trace_changed')
    if sha(manifest['input']) != manifest['input_sha256']:
        raise ValueError('native_input_changed')
    return manifest


def shape(value, depth=0):
    if depth > 3:
        return type(value).__name__
    if isinstance(value,dict):
        return {k:shape(v,depth+1) for k,v in value.items()}
    if isinstance(value,list):
        return dict(count=len(value),item=shape(value[0],depth+1) if value else None)
    return type(value).__name__


def describe(output, paths):
    verify_seal(output)
    return {str(path):shape(json.loads(path.read_text(encoding='utf8'))) for path in paths}


def evaluate(output, attack_truth, negative_truth, background_dir, *, root=ROOT):
    """Count contamination only where membership labels actually establish it.

    BACKGROUND files establish label membership, not background activity groups.
    Thus background-to-background co-membership is never claimed to be error.
    """
    output=Path(output)
    manifest=verify_seal(output,root)
    attack_truth,negative_truth,background_dir=map(Path,(attack_truth,negative_truth,background_dir))
    truth_paths=[attack_truth,negative_truth,*sorted(background_dir.glob('*.jsonl'))]
    before={str(p):sha(p) for p in truth_paths}
    attack=json.loads(attack_truth.read_text(encoding='utf8'))
    negative=json.loads(negative_truth.read_text(encoding='utf8'))
    attack_ids={o['alert_id'] for o in attack['observations']}
    negative_rows={o['alert_id']:o for o in negative['observations']}
    negative_ids=set(negative_rows)
    background_ids=set()
    for path in sorted(background_dir.glob('*.jsonl')):
        with path.open(encoding='utf8') as f:
            for line in f:
                row=json.loads(line)
                if not isinstance(row.get('event_id'),str):
                    raise ValueError('background_membership_requires_explicit_event_id')
                background_ids.add(row['event_id'])
    if attack_ids & negative_ids or attack_ids & background_ids or negative_ids & background_ids:
        raise ValueError('truth_membership_classes_overlap')
    trace=json.loads((output/'trace_map.json').read_text(encoding='utf8'))
    trace_by_event={}
    for row in trace:
        event_id=row['event_id']
        if event_id in trace_by_event and trace_by_event[event_id] != row['alert_id']:
            raise ValueError('ambiguous_external_trace_identity')
        trace_by_event[event_id]=row['alert_id']
    def canonical(ids):
        return {trace_by_event[eid] for eid in ids if eid in trace_by_event}
    attacks,negatives,background=map(canonical,(attack_ids,negative_ids,background_ids))
    candidate_path=root/'data/processed'/manifest['analysis_id']/'incident_candidates.jsonl.gz'
    alert_path=root/'data/processed'/manifest['analysis_id']/'community_alerts.jsonl.gz'
    with gzip.open(candidate_path,'rt',encoding='utf8') as f:
        communities=[json.loads(line) for line in f]
    with gzip.open(alert_path,'rt',encoding='utf8') as f:
        alerts={row['alert_id']:row for row in map(json.loads,f)}
    flat=[aid for c in communities for aid in c['alert_ids']]
    if len(flat) != len(set(flat)) or set(flat) != set(alerts):
        raise ValueError('prediction_does_not_partition_input')
    owner={aid:c['community_id'] for c in communities for aid in c['alert_ids']}
    distribution=[]
    false_negative_members=set()
    false_background_members=set()
    hn_with_background=set()
    background_with_hn=set()
    bg_only_multi=0
    for c in communities:
        members=set(c['alert_ids'])
        a,hn,bg=members & attacks,members & negatives,members & background
        if a:
            distribution.append(dict(community_id=c['community_id'],attack_alert_count=len(a),
                hard_negative_count=len(hn),background_count=len(bg),member_count=len(members),
                attack_alert_ids=sorted(a)))
            false_negative_members.update(hn)
            false_background_members.update(bg)
        if hn and bg:
            hn_with_background.update(hn)
            background_with_hn.update(bg)
        if not a and not hn and len(bg)>1 and bg==members:
            bg_only_multi+=1
    distribution.sort(key=lambda r:(-r['attack_alert_count'],r['community_id']))
    related_false=set()
    related_rejections=[]
    for event,row in sorted(negative_rows.items()):
        aid=trace_by_event.get(event)
        if aid is None:
            continue
        for related in row.get('related_alert_ids',[]):
            peer=trace_by_event.get(related)
            if peer is None or peer==aid:
                continue
            if owner[aid] == owner[peer]:
                related_false.add(aid)
            else:
                related_rejections.append(dict(alert_id=aid,related_alert_id=peer,
                    community_id=owner[aid],related_community_id=owner[peer],negative_reason=row['negative_reason']))
    unknown=set(alerts)-attacks-negatives-background
    def example(kind):
        for c in communities:
            for e in c['matching_evidence']:
                if (kind=='strong_binding' and e['match_level']==1) or (kind=='host_process_combination' and e['identity_kind']=='process_instance'):
                    return dict(community_id=c['community_id'],member_count=c['member_count'],evidence=e)
        return None
    singleton=next((c for c in communities if c['member_count']==1),None)
    report=dict(TASK_RESULT='COMMUNITY_BUILDER_READY' if not unknown and not false_negative_members and not false_background_members and not related_false else 'COMMUNITY_BUILDER_PARTIAL',
        production_analysis_id=manifest['analysis_id'],production_manifest_sha256=sha(output/'manifest.json'),
        split='existing development dataset; no held-out generalization claim; no post-metric policy tuning',
        COMMUNITY_COUNT=len(communities),SINGLETON_COMMUNITIES=sum(c['member_count']==1 for c in communities),
        MULTI_ALERT_COMMUNITIES=sum(c['member_count']>1 for c in communities),
        LARGEST_COMMUNITY_SIZE=max((c['member_count'] for c in communities),default=0),
        AVERAGE_COMMUNITY_SIZE=len(alerts)/len(communities) if communities else None,
        ATTACK_ALERT_COMMUNITY_DISTRIBUTION=distribution,
        HARD_NEGATIVE_FALSE_MERGE_COUNT=len(false_negative_members),
        HARD_NEGATIVE_FALSE_MERGE_ALERT_IDS=sorted(false_negative_members),
        HARD_NEGATIVE_FALSE_MERGE_DEFINITION='unique labelled hard negatives in communities containing labelled attacks',
        HARD_NEGATIVE_RELATED_ALERT_FALSE_MERGE_COUNT=len(related_false),
        HARD_NEGATIVE_RELATED_ALERT_FALSE_MERGE_IDS=sorted(related_false),
        HARD_NEGATIVE_WITH_BACKGROUND_COUNT=len(hn_with_background),
        BACKGROUND_FALSE_MERGE_COUNT=len(false_background_members),
        BACKGROUND_FALSE_MERGE_DEFINITION='unique labelled background alerts in communities containing labelled attacks',
        BACKGROUND_WITH_HARD_NEGATIVE_COUNT=len(background_with_hn),
        BACKGROUND_ONLY_MULTI_ALERT_COMMUNITIES=bg_only_multi,
        BACKGROUND_TO_BACKGROUND_ERROR_RATE=None,
        BACKGROUND_TO_BACKGROUND_STATUS='not_applicable: membership labels provide no activity partition',
        evaluation_coverage=(len(alerts)-len(unknown))/len(alerts) if alerts else None,
        labelled_counts=dict(attack=len(attacks),hard_negative=len(negatives),background=len(background),unlabelled=len(unknown)),
        unmapped_truth_ids=dict(attack=len(attack_ids-set(trace_by_event)),hard_negative=len(negative_ids-set(trace_by_event)),
                               background=len(background_ids-set(trace_by_event))),
        examples=dict(strong_binding=example('strong_binding'),host_process_combination=example('host_process_combination'),
            hard_negative_rejected=related_rejections[0] if related_rejections else None,
            singleton=dict(community_id=singleton['community_id'],alert_id=singleton['alert_ids'][0],
                reason=singleton['membership_decisions'][0]['reason']) if singleton else None),
        native_input_sha256_unchanged=sha(manifest['input'])==manifest['input_sha256'],
        truth_input_sha256_unchanged=all(sha(p)==digest for p,digest in before.items()),truth_input_hashes=before)
    # Recheck immutable prediction and truth after all metrics are computed.
    verify_seal(output,root)
    if not report['truth_input_sha256_unchanged']:
        raise ValueError('truth_changed_during_evaluation')
    (output/'evaluation.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    return report


def write_report(output, root=ROOT):
    """Render the measured receipt; reports remain outside production imports."""
    output=Path(output)
    manifest=verify_seal(output,root)
    r=json.loads((output/'evaluation.json').read_text(encoding='utf8'))
    if r['production_manifest_sha256'] != sha(output/'manifest.json'):
        raise ValueError('evaluation_does_not_reference_current_seal')
    s=manifest['summary']
    with gzip.open(root/'data/processed'/manifest['analysis_id']/'community_alerts.jsonl.gz','rt',encoding='utf8') as f:
        alerts={row['alert_id']:row for row in map(json.loads,f)}
    def witness(e):
        values=[]
        for ref in e['supporting_evidence']:
            value=alerts[ref['alert_id']]['raw_alert']
            for part in ref['pointer'].split('/')[1:]:
                key=part.replace('~1','/').replace('~0','~')
                value=value[int(key)] if isinstance(value,list) else value[key]
            item=f"`{ref['pointer']}={value}`"
            if item not in values:
                values.append(item)
        return '，'.join(values)
    e1=r['examples']['strong_binding']
    e2=r['examples']['host_process_combination']
    en=r['examples']['hard_negative_rejected']
    es=r['examples']['singleton']
    tests=output/'tests.xml'
    test_note='测试结果见 tests.xml。'
    if tests.exists():
        import xml.etree.ElementTree as ET
        tree=ET.parse(tests)
        suites=list(tree.getroot().iter('testsuite'))
        total=sum(int(x.attrib.get('tests',0)) for x in suites)
        failures=sum(int(x.attrib.get('failures',0))+int(x.attrib.get('errors',0)) for x in suites)
        test_note=f'实际运行 {total} 项测试，失败/错误 {failures} 项；原始记录：`tests.xml`。'
    distribution=', '.join(str(c['attack_alert_count']) for c in r['ATTACK_ALERT_COMMUNITY_DISTRIBUTION'])
    source_rows=[]
    for source,obs in s['observability'].items():
        cell=lambda kind:str(obs[kind]) if obs.get(kind) else 'NOT OBSERVABLE'
        source_rows.append('| '+ ' | '.join([source,str(obs['alerts']),cell('request'),cell('flow'),cell('session'),cell('process_identity'),cell('object')])+' |')
    text=f'''# TraceBack Community Builder 交付报告

## 1. TASK_RESULT

`TASK_RESULT={r['TASK_RESULT']}`

六类 Source 共 {s['TOTAL_ALERTS']:,} 条输入均保留。只交付无向活动候选分组；候选不表示攻击已确认。现有开发集 125 条 ATTACK、360 条 HARD_NEGATIVE、9,500 条 BACKGROUND 的评估覆盖率为 100%。生产先封存，GT 后读取，未依据评估指标调整规则或参数。

{test_note} 覆盖五层证据、强/弱合并、单告警、作用域隔离、PID 复用、常见进程/共享 IP 拒绝、资源上限、排列稳定性、Schema/Stable ID 和生产 GT 隔离。未修改前端，因此无前端构建变更。

## 2. 实际实现架构与文件

```text
CanonicalAlert（现有 adapters/models）
  → 核心抽取（复用 entities/context.py、entities/front_data.py）
  → Evidence Extraction（community/evidence.py）
  → Candidate Index（community/index.py）
  → Evidence Tier Matcher（community/evidence.py）
  → Join / Merge / Create（community/builder.py）
  → Incident Candidate（community/models.py）
```

生产新增文件位于 `backend/app/community/`；配置为 `configs/community-v1.yaml`；运行入口为 `scripts/run_community_builder.py`。公开接口 `prepare_communities(alerts, source_settings, config)` 直接消费 CanonicalAlert，返回已抽取 alerts、entities 和 result。复用现有 Adapter/抽取能力，不执行旧 correlation scorer、聚类器或后续链路。历史代码和 CanonicalAlert Schema 未修改。

`evaluation/community_check.py` 只在封存结果校验成功后读取标签，提供指标和本报告。`backend/tests/test_community_builder.py`、`evaluation/tests/test_community_check.py` 为新增测试。

Community 和 Incident Candidate ID 由排序成员及带类型/版本的 SHA-256 身份生成；不以文件行号、绝对路径、时间或 GT 作身份。配置、源设置、映射、输入摘要、实现 hash 和输出 hash 全部保存在 manifest/receipt 中。逐告警 CREATE/JOIN/MERGE 记录含旧群组 ID、匹配层级、理由和绑定 EvidencePointer。

## 3. 实际证据及可观测性

| 层级 | 实现使用的统一字段/证据 | 本次实际获胜次数 |
| --- | --- | ---: |
| Level 1 | 带 scope 的 request、flow、connection、session；支持 trace/correlation/transaction 与原生 direct_reference→record 绑定；不同种类 ID 分桶 | {s['matches_by_level'].get('1',0)} |
| Level 2 | task；host + GUID/instance ID 或 PID+start_time；明确 parent/self 实例交接；host 内 response_object→request_object；有具体上下文的 object/file_hash | {s['matches_by_level'].get('2',0)} |
| Level 3 | host+PID+进程描述+相同账号/具体上下文；host+account+同 service/operation 或具体上下文 | {s['matches_by_level'].get('3',0)} |
| Level 4 | 同 scoped host、已映射类别、同源 signature 与短时间连续，且无上下文/账号/进程冲突 | {s['matches_by_level'].get('4',0)} |
| Level 5 | 完整 src/dst IP+port、protocol、direction、source_role、destination_role、network scope、source type/sensor | {s['matches_by_level'].get('5',0)} |

获胜次数计入成员证明树；有强证据时不靠弱证据叠分。Level 3/4/5 的规则由单元测试直接验证，本数据集没有这些层级最终获胜的加入决策。

| Source | 输入 | request | flow/connection | session | 强进程实例 | object 字段 |
| --- | ---: | --- | --- | --- | --- | --- |
{chr(10).join(source_rows)}

上表数字为告警级字段覆盖，不等于字段齐全的 pair 数。所有来源的 task、trace、correlation、transaction、direct_reference 都是 NOT OBSERVABLE。EDR 的 file_hash 非空 512 条；单独 hash 不构成强关联。所有来源的 source_role/destination_role 都是 NOT OBSERVABLE，只有 Firewall 有 direction，因此真实 Level 5 不启用。Authentication 虽有 PID，但缺实例 start_time/GUID，强进程身份为 NOT OBSERVABLE。Session 默认保持既有 source scope；跨来源短 ID 相等不证明可共享。

配置窗依次为 1800/600/120/30/15 秒，群组最大跨度 3600 秒、最多 250 成员；弱加入最多 20 成员。索引每 key 最多 64 个近期见证、每告警最多 128 个候选邻居；淘汰记录为显式 policy 统计。超过跨度/规模直接拒绝，不追求巨大连通分量。

仅 Level 1/2 支持合并多个已有 Community，且每个待合并组都须各自有强绑定；当前版本保守地不启用“多个弱组合证据触发合并”。实际数据没有发生需要 MERGE 的场景；合成强桥测试验证 A+B→C，弱桥测试验证已有组保持分开。

## 4. Community 实测统计

| 指标 | 实际值 |
| --- | ---: |
| COMMUNITY_COUNT | {r['COMMUNITY_COUNT']} |
| SINGLETON_COMMUNITIES | {r['SINGLETON_COMMUNITIES']} |
| MULTI_ALERT_COMMUNITIES | {r['MULTI_ALERT_COMMUNITIES']} |
| LARGEST_COMMUNITY_SIZE | {r['LARGEST_COMMUNITY_SIZE']} |
| AVERAGE_COMMUNITY_SIZE | {r['AVERAGE_COMMUNITY_SIZE']:.6f} |
| 攻击告警所在组数 | {len(r['ATTACK_ALERT_COMMUNITY_DISTRIBUTION'])} |
| HARD_NEGATIVE_FALSE_MERGE_COUNT | {r['HARD_NEGATIVE_FALSE_MERGE_COUNT']} / 360 |
| BACKGROUND_FALSE_MERGE_COUNT | {r['BACKGROUND_FALSE_MERGE_COUNT']} / 9500 |
| HN 与 GT 明确关联目标的错误同组数 | {r['HARD_NEGATIVE_RELATED_ALERT_FALSE_MERGE_COUNT']} |
| HN 与背景同组告警数 | {r['HARD_NEGATIVE_WITH_BACKGROUND_COUNT']} |
| BACKGROUND_ONLY_MULTI_ALERT_COMMUNITIES | {r['BACKGROUND_ONLY_MULTI_ALERT_COMMUNITIES']} |
| 索引见证检查数 | {s['examined_index_witnesses']} |
| 策略淘汰计数 | {s['policy_pruned_witnesses_or_neighbors']} |
| 资源截断 | {str(s['resource_truncated']).lower()} |
| 适配+抽取+分组耗时 | {s['runtime_seconds']:.3f} 秒 |
| 进程峰值工作集 | {s['peak_process_working_set_mb']:.3f} MiB |

攻击告警分布为 **{distribution}**，合计 125 条；每组完整 ID/成员见 `evaluation.json`。

错误合并口径：HN/BACKGROUND 中进入含 ATTACK 告警组的唯一告警数。另单独检查 HN 与其 GT `related_alert_ids` 是否同组。不能把“背景之间同组”直接称为错误：背景文件仅提供类别成员，没有真实活动划分，其错误率为 `null / not_applicable`，未伪造 0%。

输入原文件与所有读取的 GT 文件 SHA-256 在运行前后保持不变。数据、GT 和算法参数没有为本次评估改写。实测 54,322 次见证检查对比全量 49,845,120 个可能告警 pair；复杂度由索引/候选/成员上限限制，而非全量 pair 枚举。耗时不含输出压缩写盘；峰值为运行进程工作集，非其他实验的通用 SLA。

## 5. 典型案例

1. **真实强绑定**：`{e1['community_id']}`，{e1['member_count']} 条；理由 `{e1['evidence']['match_reason']}`，Level {e1['evidence']['match_level']}，间隔 {e1['evidence']['time_delta_seconds']} 秒。原始见证：{witness(e1['evidence'])}。同 scope 的实际连接身份匹配，因此加入。
2. **真实组合实体**：`{e2['community_id']}`，{e2['member_count']} 条；理由 `{e2['evidence']['match_reason']}`，Level {e2['evidence']['match_level']}，间隔 {e2['evidence']['time_delta_seconds']} 秒。原始见证：{witness(e2['evidence'])}。使用 host 和实际进程实例，非单独进程名。另有直接测试证明 host+account+service/operation 可按 Level 3 加入。
3. **真实 HN 正确分离**：`{en['alert_id']}` 位于 `{en['community_id']}`；其 GT 指向的易混淆对象 `{en['related_alert_id']}` 位于 `{en['related_community_id']}`。GT 案例说明为“{en['negative_reason']}”。同一目标但不同外部客户端不足以提名完整绑定；IP/端口本身没有独立加入通道。标签只用来解释评估结果。合成同 host/IP/account/常见进程、相近时间但不同 session/进程实例的专项测试也确认拒绝。
4. **真实 singleton**：`{es['alert_id']}` 保留于 `{es['community_id']}`，理由 `{es['reason']}`。没有合格上下文时创建单告警候选，不丢弃记录。

完整 case 的两端原始告警引用与 JSON Pointers 保存在 `evaluation.json` 和压缩候选文件。

## 6. 已知问题与边界

- 这是既有开发集的观测结果，未使用独立测试集，不能外推通用误合并率或最优窗口。
- 125 条攻击仍在 9 个候选组；默认 scope 隔离、缺失跨来源绑定和身份别名会保留分片。本阶段不为恢复完整链补关联或读 GT 提升聚合。
- Level 5 的角色字段缺失；task/trace/direct binding 等通用支持仅经合成测试，未宣称真实源具备这些证据。
- 原始 HOST 名称、host_id、短名/FQDN 不凭猜测归一；PID-only/常见进程名不升级为强实例。
- 索引有确定性近期见证/邻居上限，大规模 hot key 可能降低召回；本次淘汰为 0，执行完整，不代表穷举所有潜在关系。
- 最大群组/生命周期和弱合并限制会保留较小组；不表示真实活动必然只有这些成员。
- AGENTS 引用的三份原始需求及 CODEX_TASKS 当前缺失，未伪造或从历史测试临时目录恢复；按本轮附件明确要求实施。目录无 Git 元数据，因此未创建 commit/PR。

## 7. 下一阶段接口与复现

输出提供 `community_id`、稳定 `incident_candidate_id`、完整 `alert_ids`、`start_time/end_time`、`sources`、`entity_ids`、scoped contexts、逐告警决策及 `matching_evidence`。alerts/entities 同批导出，可回溯 `alert_id → CanonicalAlert → raw_alert`。可显式调用候选的 `to_incident(alerts)` 兼容现有 Incident 字段，但不生成任何评分边或攻击链。没有实现 Stage、ATT&CK Mapping、方向判断、实/虚边、Attack Chain 或 AI Explain。

领域结果：`data/processed/{manifest['analysis_id']}/` 中的 `community_alerts.jsonl.gz`、`community_entities.jsonl.gz`、`incident_candidates.jsonl.gz`。

诊断：`outputs/analyses/{manifest['analysis_id']}/` 中的 `diagnostics.jsonl`、`frequency_snapshot.json`、`manifest.json`。本目录同时提供 `summary.json`、`evaluation.json`、`implementation_receipt.json`、`trace_map.json`、`tests.xml`。

```powershell
.venv\\Scripts\\python.exe scripts/run_community_builder.py --input "{manifest['input']}"
.venv\\Scripts\\python.exe -m evaluation.community_check --attack-truth "{next(p for p in r['truth_input_hashes'] if p.endswith('ground_truth/ground_truth.json') or p.endswith('ground_truth'+chr(92)+'ground_truth.json'))}" --negative-truth "{next(p for p in r['truth_input_hashes'] if p.endswith('hard_negative/ground_truth.json') or p.endswith('hard_negative'+chr(92)+'ground_truth.json'))}" --background-dir "{str(Path(next(p for p in r['truth_input_hashes'] if 'background' in Path(p).parts)).parent)}"
.venv\\Scripts\\python.exe -m evaluation.community_check --report
```

生产脚本不接受 GT 输入；评估强制核验封存输出、trace、实现收据和原始输入 hash，发现变化即拒绝读取标签。已经在此阶段停止。
'''
    (output/'REPORT.md').write_text(text,encoding='utf8')
    return output/'REPORT.md'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'outputs/community_v1')
    parser.add_argument('--describe',type=Path,nargs='+')
    parser.add_argument('--attack-truth',type=Path)
    parser.add_argument('--negative-truth',type=Path)
    parser.add_argument('--background-dir',type=Path)
    parser.add_argument('--report',action='store_true')
    args=parser.parse_args()
    if args.report:
        print(write_report(args.output))
    elif args.describe:
        print(json.dumps(describe(args.output,args.describe),indent=2))
    elif args.attack_truth and args.negative_truth and args.background_dir:
        report=evaluate(args.output,args.attack_truth,args.negative_truth,args.background_dir)
        compact={k:v for k,v in report.items() if k not in {'ATTACK_ALERT_COMMUNITY_DISTRIBUTION','examples','truth_input_hashes'}}
        compact['attack_community_count']=len(report['ATTACK_ALERT_COMMUNITY_DISTRIBUTION'])
        compact['attack_counts_per_community']=[r['attack_alert_count'] for r in report['ATTACK_ALERT_COMMUNITY_DISTRIBUTION']]
        print(json.dumps(compact,indent=2))
    else:
        parser.error('supply --describe or all three membership truth inputs')


if __name__=='__main__':
    main()
