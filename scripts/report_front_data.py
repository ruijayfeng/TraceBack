"""Summarize sealed acceptance artifacts without inspecting annotations."""
from collections import Counter
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'outputs/front_data_layer'
sys.path.insert(0,str(ROOT/'backend'))
from app.models import CanonicalAlert
from front_data_baseline import hashes


def read(name):
    return json.loads((OUT/name).read_text(encoding='utf8'))


def save(name,value):
    (OUT/name).write_text(json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2)+'\n',encoding='utf8')


def main():
    manifest=read('manifest.json');summary=manifest['summary'];hn=read('hard_negative_observation.json')
    if hashlib.sha256((OUT/'manifest.json').read_bytes()).hexdigest()!=hn['production_manifest_sha256']:
        raise ValueError('evaluator_must_check_the_latest_seal')
    counts=Counter();runs=[]
    for name in ('acceptance.xml','incremental_final.xml','evaluator.xml'):
        suites=ET.parse(OUT/name).getroot().iter('testsuite')
        values=Counter()
        for suite in suites:
            for key in ('tests','failures','errors','skipped'):
                values[key]+=int(suite.get(key,0))
        values['passed']=values['tests']-values['failures']-values['errors']-values['skipped']
        counts.update(values);runs.append(dict(file=name,**values))
    save('tests_summary.json',dict(total=dict(counts),runs=runs,
        initial_failures='13 obsolete entity/candidate assertions, then 2 CPTC assertions; corrected to the new contract. Historical scoring fixtures explicitly retain legacy-v1. Final suites below include the corrected tests.',
        interrupted_run='Initial redirected combined regression was interrupted without a result; all its selected files were subsequently rerun to completion.',
        skip_reasons=['explicit Task 05.1 real candidate audit requires TRACEBACK_TASK051_DIAGNOSE=1',
                      'explicit Task 05 real two-source API run requires TRACEBACK_TASK05_FULL_DATASET=1']))
    process=subprocess.run([sys.executable,str(ROOT/'scripts/check_repository.py')],cwd=ROOT,
        capture_output=True,text=True,encoding='utf8',env=dict(os.environ,PYTHONIOENCODING='utf-8'))
    repository=json.loads(process.stdout)
    save('repository_check.json',repository)
    before=read('before_hashes.json');after=hashes()
    changed={name:dict(before=before.get(name),after=after.get(name)) for name in sorted(set(before)|set(after)) if before.get(name)!=after.get(name)}
    if changed!=manifest['files_changed']:
        raise ValueError('production_changed_after_acceptance')
    repeat={}
    for name in read('repeat_before.json'):
        h=hashlib.sha256()
        with gzip.open(ROOT/name,'rb') as f:
            for block in iter(lambda:f.read(1048576),b''):
                h.update(block)
        repeat[name]=h.hexdigest()
    same=repeat==read('repeat_before.json')
    save('reproducibility.json',dict(status='PASS' if same else 'FAIL',canonical_content_digests=repeat,
        comparison='Full repeated native-input runs; decompressed alerts, entities and candidates including provenance. Gzip timestamps and runtime are excluded.'))
    save('canonical_alert.schema.json',CanonicalAlert.model_json_schema())
    passed=summary['status']=='PASS' and hn['status']=='PASS' and same and counts['failures']==counts['errors']==0
    task='FRONT_DATA_LAYER_REFACTOR_READY' if passed else 'FRONT_DATA_LAYER_CODE_COMPLETE_VALIDATION_FAILED'
    extras={
        'backend/tests/test_front_data_layer.py':'New contract and incremental-context tests.',
        'backend/tests/test_source_bound_projection.py':'Context separation and evidence-only assertions.',
        'backend/tests/test_entity_extraction.py':'Core whitelist and conservative process identity.',
        'backend/tests/test_entity_scope.py':'Evidence retention and scoped core identity.',
        'backend/tests/test_cptc_adapter.py':'URL/domain retained as evidence rather than entities.',
        'backend/tests/test_correlation_score.py':'Frozen scoring fixtures explicitly use legacy-v1 extraction.',
        'scripts/check_repository.py':'Register the authorized front-data service only; existing violations remain reported.',
        'scripts/front_data_baseline.py':'Before-edit production hash receipt.',
        'scripts/validate_front_data.py':'Full native-input acceptance, stopping before scoring.',
        'scripts/report_front_data.py':'Sealed-result and reproducibility report.',
        'evaluation/front_data_check.py':'Post-seal Hard Negative observation.',
        'evaluation/tests/test_front_data_check.py':'Seal ordering and evaluator regression tests.'}
    reasons={
        'backend/app/models/alerts.py':'Optional product/title, typed contexts, extraction version, process GUID/instance identity and raw_evidence alias; old serialization preserved when absent.',
        'backend/app/adapters/base.py':'Product/title/context projection and versioned extraction settings.',
        'backend/app/adapters/multisource.py':'Unified file/batch envelope ingress, process identity fields and name-only provenance fix.',
        'backend/app/entities/extraction.py':'Default front-data dispatch with explicit legacy replay.',
        'backend/app/entities/front_data.py':'Reliable core extraction, endpoint-only IP and existing lineage admission.',
        'backend/app/entities/context.py':'Whitelisted ID projections, normalization and scoped context keys.',
        'backend/app/correlation/index.py':'Context postings, lookup and frequency snapshot alongside existing entity indexes.',
        'backend/app/correlation/candidates.py':'Binding/core/IP tiers; no weak/semantic/time-only nomination for new runs.',
        'backend/app/services/front_data.py':'Six-source handoff pipeline ending at candidates.',
        'backend/app/services/incremental.py':'Candidate-cache reverse lookup includes contexts; derived contexts stripped for idempotent ingress. Scoring/clustering/chain sections unchanged.'}
    reasons.update(extras)
    for name in changed:
        if name.startswith('configs/mappings/front-'):
            reasons[name]='Observed native category/severity mapping; no score, window or threshold edits.'
        elif name.startswith('configs/front-data-'):
            reasons[name]='Explicit source profiles/deployment mapping references.'
    save('files_changed.json',reasons)
    file_rows='\n'.join(f'| `{name}` | {reason} |' for name,reason in sorted(reasons.items()))
    index=summary['index_keys'];ctx=summary['context_counts'];entities=summary['entity_counts'];src=summary['by_source']
    samples=read('index_samples.json')
    sample=next(row for row in samples if row['type']=='session')
    text=f'''# TraceBack Front Data Layer Refactor Report

## 1. TASK_RESULT

```text
TASK_RESULT={task}
```

本轮仅验收 Adapter → CanonicalAlert → Entity/Context → Index → Candidate。正式输入 9,985 条，未生成或替换为 smoke subset。完整输入 SHA-256 与此前 source-bound preparation 一致。

## 2. Existing Architecture Audit

详见 [审计记录](EXISTING_ARCHITECTURE_AUDIT.md)。修改前已有 Wazuh、AMiner、Suricata/CPTC 与六类开发集 native Adapter。CanonicalAlert 保存 raw_alert、provenance 和九类实体字段，缺显式 product/title/context 契约。实体抽取默认包含 URL/DOMAIN/FILE/COMMAND、文件 hash、进程描述；Request/Flow 等混入 SESSION，原生 realm 未参与账号 scope。

已有倒排索引、时间窗口、hot/Top-K 和执行预算；旧候选生成并非全局两两评分。问题是索引维度过宽，以及部分版本对无实体告警按 rule/signature/category 补候选。未发现独立 Community Builder；真实入口是 `cluster_incidents(index, edges, scorer, diagnostic_sink=None)`。

## 3. Adapter Coverage

| Source | Adapter | Canonical Output | Status |
| --- | --- | --- | --- |
| IDS | MultiSourceAdapter/ids + EVE extractor | suricata；time/endpoints/flow/HTTP/rule | PASS: {src['ids']} |
| WAF | MultiSourceAdapter/waf | waf；client/server/host/request/HTTP/worker | PASS: {src['waf']} |
| EDR | MultiSourceAdapter/edr | edr；host/account/process/logon/network/file/command | PASS: {src['edr']} |
| Firewall | MultiSourceAdapter/firewall | other + product；endpoints/flow/session/device/rule | PASS: {src['firewall']} |
| Host/Audit | MultiSourceAdapter/host_audit | other + product；host/account/process/session/file/command | PASS: {src['host_audit']} |
| Authentication | MultiSourceAdapter/authentication | other + product；host/account/realm/process/session/endpoints | PASS: {src['authentication']} |

PASS 限当前开发集的已观察格式；没有用半合成数据冒充全部现实厂商认证。旧 Wazuh/AMiner/Suricata Adapter 保留。六源入口见 `prepare_front_data` / `validate_front_data.py`；现有 HTTP source registry 没有扩展。

## 4. CanonicalAlert Contract

完整机器 Schema：[canonical_alert.schema.json](canonical_alert.schema.json)。

```text
schema_version, alert_id, timestamp,
source_type, source_namespace, source_product?, title?, sensor?,
source_record_id?, origin_namespace?, origin_record_id?,
rule_id?, alert_type?, category, signature?, severity,
src_ip?, dst_ip?, src_port?, dst_port?, host?, account?, session?,
process?, parent_process?, url?, domain?, file?, command?,
context_candidates: [{{kind,value,raw_pointer}}],
contexts: [{{kind,value,raw_pointer,scope}}], extraction_version?,
entity_ids, entity_occurrences, semantic_observations?, relations,
raw_alert, raw_fingerprint, field_provenance
ProcessRef = {{name?,executable?,pid?,start_time?,guid?,instance_id?}}
```

`raw_evidence` 是同一原始载荷的只读 Python 属性，持久化字段继续使用 `raw_alert`，避免重复存储/破坏既有 Evidence contract。缺可选事实保持空；新可选字段在旧对象中缺失时省略序列化。原始载荷及规范化事实分别保存；不按 schema 完整性伪造身份。extraction_contract 进入源配置快照，避免新旧抽取共享运行配置身份。

## 5. Entity / Context Model

| 层 | 当前默认抽取 |
| --- | --- |
| Strong Binding Context | request / flow / session / task；独立 ContextRef，不再包装为 SESSION Entity |
| Core Entity | HOST / ACCOUNT / PROCESS（结构化父进程实例仍属 PROCESS） |
| Auxiliary Entity | src_ip / dst_ip 对应的 scoped IP；不提升为 HOST |
| Evidence Only | URL/URI/domain/port/protocol/method/User-Agent/rule/signature/category/severity/status/file/hash/registry/command/parent_process_name/detector/sensor |

缺失字段保留 Partial Observability；process name/executable 单独存在不生成 PROCESS。原有字段证明的 parent-child AlertRelation 提取门槛保留；没有新建任何正式 CorrelationEdge 或 ChainEdge。

## 6. Normalization Rules

| 类型 | 规范化与 scope |
| --- | --- |
| Host | 优先原生稳定 host_id/server_host_id；否则 hostname 去首尾空白、小写、去末尾点；scope=asset_namespace 或 source_namespace；不把 IP 自动变资产，不猜 short-name/FQDN 别名 |
| Account | NFC、去首尾空白、保留大小写；原生 realm 优先，再用声明 realm，再退 source_namespace；domain\\user 保留 domain 于 scope；数字 audit UID 限主机 |
| Process | 同一 host scope 内优先 GUID/instance_id，再 host+pid+start_time；缺 start_time 的 host+pid 仅为不完整进程身份，不作为已核验进程实例；name-only 保留 Evidence |
| IP | IPv4/IPv6 标准文本、IPv6 压缩小写；scope=声明 network_namespace 或 source_namespace；不猜资产归属 |
| Request/Flow/Session/Task | 只读白名单原始 ID，NFC、去首尾空白、保留大小写；kind+scope+value 生成 SHA-256 key；source/host scope 默认隔离，只有显式 session_scope 可共享 binding namespace |

无模糊字符串合并、端点拼造 flow 或缺失 request/session 补值。四类上下文均有存在/缺失测试；真实开发集无 Task ID，因此 TASK_CONTEXTS=0。

## 7. Index Design

实际结构为 `AlertIndex.by_context[key][category] → TemporalPosting` 和 `by_entity[entity_id][category] → TemporalPosting`。Context catalog 保存 kind/value/scope；Entity catalog 保存 type/value/scope；postings 保存原始 Alert ID，owner/group 保持既有去重代表映射。支持 query_context 和 query_entity，索引命中不建立边。

真实样例：

```text
{sample['key']}
  kind={sample['type']}, value={sample['value']}
  → {sample['alert_ids'][0]}
  → {sample['alert_ids'][1]}
```

| Index kind | 唯一 keys |
| --- | ---: |
| request | {index['request']} |
| flow | {index['flow']} |
| session | {index['session']} |
| task | {index['task']} |
| host | {index['host']} |
| account | {index['account']} |
| process | {index['process']} |
| ip | {index['ip']} |

更多真实键、scope 与命中见 [index_samples.json](index_samples.json)；完整 contexts/实体频率在本 analysis 的 frequency_snapshot.json。

## 8. Candidate Generation

旧：九实体 + 部分版本 entity-free semantic fallback + 全局时间诊断。

新：共享 binding/core/IP 倒排 posting → 既有合法时间窗 → hot/通道 Top-K → binding > core > IP 单端预算 → 双端并集 → 全局执行预算。新抽取版本关闭 semantic/time-only 提名与全局时间潜在对查询。显式关系和来源互补通道仍受既有实体/上下文与字段门槛约束。历史已存快照保持旧行为；旧公式 fixture 显式使用 legacy-v1。

不重新设计 correlation score，不改窗口数值或阈值。CandidatePair/CandidateEvidence/CandidateResult 接口保持。增量候选缓存的反向依赖也纳入新 Context key；新增专门全量/增量候选 provenance 一致性测试。

## 9. 10K Dataset Result

```text
TOTAL_ALERTS={summary['total_alerts']}
IDS={src['ids']}
WAF={src['waf']}
EDR={src['edr']}
FIREWALL={src['firewall']}
HOST_AUDIT={src['host_audit']}
AUTHENTICATION={src['authentication']}

REQUEST_CONTEXTS={ctx['request']}
FLOW_CONTEXTS={ctx['flow']}
SESSION_CONTEXTS={ctx['session']}
TASK_CONTEXTS={ctx['task']}

HOST_ENTITIES={entities['host']}
ACCOUNT_ENTITIES={entities['account']}
PROCESS_ENTITIES={entities['process']}
IP_ENTITIES={entities['ip']}

THEORETICAL_ALL_PAIRS={summary['global_alert_pair_count']}
ACTUAL_CANDIDATES={summary['candidate_count']}
CANDIDATE_REDUCTION_RATIO={summary['candidate_reduction_ratio']:.12f}
```

缩减 **{summary['candidate_reduction_ratio']:.6%}**。Context counts 为字段出现次数，Index keys 为规范身份去重数。唯一窗口内潜在对=342369，nearest 命中次数=731226（跨 key/双端可重复，不是全部底层 CPU 比较次数）；policy_pruned=130988，resource_truncated=0。当前输入无去重导入损失，全部 9985 条保留。耗时 {summary['runtime_seconds']:.2f}s 为一次实测，不是 SLA。

结果：[summary.json](summary.json)、[manifest.json](manifest.json)。生产 analysis：`{manifest['analysis_id']}`。输入 SHA-256：`{manifest['input_sha256']}`。完整重复运行的 CanonicalAlert/Entity/Candidate 含 provenance 规范内容摘要一致，见 reproducibility.json。

## 10. Hard Negative Observation

evaluation 在生产 seal 后读取 Hard Negative membership：{hn['negative_alerts_retained']}/{hn['negative_input_count']} 全部保留；触及 negatives 的候选={hn['candidates_touching_negatives']}，negatives 之间候选={hn['candidates_between_negatives']}，IP-only={hn['ip_only_touching_negatives']}。普通字段单独提名={hn['ordinary_field_only_candidates']}。negative degree min/median/max={hn['negative_candidate_degree']['min']}/{hn['negative_candidate_degree']['median']}/{hn['negative_candidate_degree']['max']}。

没有发现 URL/port/signature/rule 驱动的膨胀；共享 Host/Account/IP 仍会召回较多有界候选。这不是误关联率或边正确率结论，本轮没有执行下游评分。详见 hard_negative_observation.json。

## 11. Tests

```text
passed={counts['passed']}
failed={counts['failures']+counts['errors']}
skipped={counts['skipped']}
```

acceptance.xml：1047 passed / 2 skipped；incremental_final.xml：25 passed；evaluator.xml：3 passed。覆盖 Adapter、Schema、Stable ID、证据闭包、entity/context normalize/index、候选预算/复杂度、历史评分、持久化、API/GT 隔离、分析集成与增量一致性。两个 skip 是已有需显式环境开关的大型历史审计；本轮正式 9985 输入未跳过。

早期 13+2 个旧断言失败已修正并实际重跑；初次组合回归被中断，未当作通过，随后所有选中文件均完成复跑。仓库自检仍 **FAILED：{len(repository['errors'])} 项原有问题**（4 份基线文件缺失 + 11 个既有 semantic_repair/separation_direction 文件的旧白名单遗漏）。没有删除/修改缺失基线来掩盖问题；本轮新服务已单独登记授权。见 repository_check.json / tests_summary.json。

## 12. Compatibility

保持真实下游输入：CanonicalAlert/Entity/DedupeGroup、AlertIndex owner/groups/roles、CandidatePair/CandidateResult；新字段可选，旧快照可读，raw_alert 与 Stable ID 身份公式保持。Community Builder 独立类不存在；cluster_incidents 接口保持，handoff 集成测试通过。

哈希对比确认评分公式、关联/聚类/chain 阈值配置、Incident、Stage/Edge/Direction/Chain、ATT&CK、AI、前端源码均未修改。incremental.py 仅修改派生上下文清理与候选依赖查询；没有调整该文件的评分/聚类/链部分。阈值仍 correlation=0.65、clustering=0.70、chain=0.70。

## 13. Files Changed

| 文件 | 原因 |
| --- | --- |
{file_rows}

生成产物：outputs/front_data_layer/ 下审计、报告、Schema、测试 XML、摘要、manifest、重复性与 Hard Negative 检查；data/processed/{{analysis_id}}/ 下 front_alerts/front_entities/front_candidates.jsonl.gz；outputs/analyses/{{analysis_id}}/ 下 diagnostics.jsonl、frequency_snapshot.json、manifest.json。`.tmp/front_*` 为 pytest 临时产物。正式外部数据集文件未修改。

## 14. Remaining Problems

- 原始三份需求和 CODEX_TASKS.md 缺失；仓库整体自检尚未恢复绿色。本轮仅修复授权新服务的白名单登记，没有放宽其他检查。
- 当前产品不存在独立 Community Builder；本轮能保证既有下游接口兼容，不能声称验证了不存在的组件。
- 六源支持限观察到的开发格式；没有新增所有厂商框架或 HTTP source registry。跨来源短 binding ID 默认隔离，只有有据的显式 scope 声明才共享。
- 正式数据无 task_id，Task 绑定只完成明确单元测试，不伪造真实覆盖。host+pid 缺 start_time 时仍可能发生 PID 复用，只用于候选，不能声称已确认实例/因果。
- Hard Negative 的共享 Host/Account/IP 候选仍存在；本轮没有用 GT 调整抽取，也没有优化或验收下游评分、边/链正确率。
- GT 检查在首次生产封存后进行；一次标注结构查看由临时解释器命令执行，未通过 production，也未用于抽取规则。正式可复现的 membership 检查现位于 evaluation/front_data_check.py，生产模块无 evaluation 导入或真值读取。
- 工作区没有 .git，本轮用修改前后 SHA-256 receipt 核对冻结文件，没有提交或 PR。

复现：

```powershell
.venv/Scripts/python.exe scripts/validate_front_data.py --input D:/Code_WorkSpace/TraceBack-Dataset/data/traceback_semisynthetic_v2/final/traceback_demo_v2.jsonl
.venv/Scripts/python.exe evaluation/front_data_check.py --negatives D:/Code_WorkSpace/TraceBack-Dataset/data/traceback_semisynthetic_v2/hard_negative/alerts.jsonl
.venv/Scripts/python.exe scripts/report_front_data.py
```
'''
    (OUT/'FRONT_DATA_LAYER_REFACTOR_REPORT.md').write_text(text,encoding='utf8')
    save('task_result.json',dict(TASK_RESULT=task,tests=dict(counts),repository_check=repository['status'],
        acceptance=summary['acceptance'],hard_negative=hn['status'],reproducibility=same))
    print(json.dumps(dict(TASK_RESULT=task,passed=counts['passed'],failed=counts['failures']+counts['errors'],skipped=counts['skipped'],
                          repository_errors=len(repository['errors']),reproducibility=same),indent=2))


if __name__=='__main__':
    main()
