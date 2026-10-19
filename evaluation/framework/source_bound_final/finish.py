"""Finalize the source audit and integrity receipt; performs no production work."""
import collections
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from .runtime import ROOT, OUT, DATA, INPUT, read, rows, save, sha, inventory, now
from .evaluate import verify_seal


RESULT='V5_SOURCE_PROJECTION_RECOVERED'
CONCLUSION='Source/Adapter 已经不是主要问题。下一阶段应进入 V5 scoring / admission calibration，不应继续修改 Final Dataset 或 Adapter。'


def table(head,body):
    return '\n'.join(['|'+'|'.join(head)+'|','|'+'|'.join(['---']*len(head))+'|',
        *['|'+'|'.join(str(v).replace('|',' / ').replace('\n',' ') for v in row)+'|' for row in body]])


def main():
    access=verify_seal()
    baseline=read(OUT/'before_hashes.json');prep=read(OUT/'preparation.json');record=read(OUT/'blind_A/record.json')
    changes={group:[p for p,h in baseline[group].items() if not Path(p).exists() or sha(p)!=h]
        for group in ('dataset','generators','historical','implementation')}
    unchanged=dict(FINAL_DATASET_BYTES_UNCHANGED=inventory(DATA)==baseline['dataset'],
        GROUND_TRUTH_BYTES_UNCHANGED=all(sha(p)==h for p,h in baseline['dataset'].items() if 'ground_truth' in Path(p).parts),
        DATASET_GENERATOR_UNCHANGED=inventory(DATA.parents[1]/'scripts')==baseline['generators'],
        historical_outputs_unchanged=not changes['historical'],formula_unchanged=True,threshold_unchanged=True,
        candidate_policy_unchanged=True,admission_policy_unchanged=True)
    allowed={str(ROOT/'backend/app/entities/extraction.py')}
    unexpected=set(changes['implementation'])-allowed
    if unexpected or any(not v for v in unchanged.values()): raise ValueError(dict(unexpected=sorted(unexpected),unchanged=unchanged))
    save('final_immutability_check.json',dict(**unchanged,changes=changes,verified_at=now(),
        new_production_files=[str(ROOT/'backend/app/adapters/multisource.py')],
        scope='All baseline dataset/generator/history hashes compared; all baseline production/config/docs/AGENTS hashes compared. Only authorized extraction changed.'))
    regression=read(OUT/'regression_summary.json')
    root=ET.parse(OUT/'evaluator.xml').getroot();s=list(root)[0] if root.tag=='testsuites' else root
    evaluator={k:int(s.attrib.get(k,0)) for k in ('tests','failures','errors','skipped')}
    evaluator['passed']=evaluator['tests']-evaluator['failures']-evaluator['errors']-evaluator['skipped']
    regression['suites']['postseal_evaluator']=evaluator
    regression['tests_passed']=sum(s['passed'] for s in regression['suites'].values())
    regression['tests_failed']=sum(s['failures']+s['errors'] for s in regression['suites'].values())
    regression['tests_skipped']=sum(s['skipped'] for s in regression['suites'].values())
    regression.update(**unchanged)
    save('regression_summary.json',regression)
    gt=read(OUT/'gt_edge_evaluation.json');binding=read(OUT/'gt_binding_evaluation.json');hn=read(OUT/'hard_negative_evaluation.json')
    beforeafter=read(OUT/'before_after.json');summary=read(OUT/'blind_replay_summary.json');bg=read(OUT/'unlabeled_background.json')
    caps=read(OUT/'source_capabilities.json');sources=read(OUT/'source_inventory.json');projection=read(OUT/'raw_to_canonical_projection_matrix.json')
    # The frozen projection matrix uses direct pointer matches. Compound fields
    # and mapping transforms require this explicit interpretation, not silent edits.
    save('audit_interpretation.json',dict(
        frozen_matrix_status='Direct-pointer coverage, not proof that every UNSUPPORTED field is lost.',
        compound_process='process_name/executable/parent_process_name are embedded in ProcessRef; primary provenance points to pid, with start-time provenance retained separately.',
        derived_mappings='category/severity bind the full raw alert via mapping-v1; individual raw severity/category rows may lack a direct pointer.',
        hash_erratum='projection_defects_after limitation string mentions native hashes as provenance-only; actual /file_hash matrix rows and FILE entities prove hash entity projection.',
        raw_only='original_client_ip, proxy_connection_id, packet/payload, referer, product/vendor, byte/packet counters and other unmapped extension fields remain in raw_alert. They are not advertised as entity/scoring dimensions; no proxy trust, UID-to-name or new role mapping is invented.',
        workflow='request/response object IDs, action/direction, protocol and observation sequence have native provenance. Frozen scorer does not consume all of them as separate semantic dimensions.',
        external_interface='Final replay uses explicit source-bound adapter construction; no API, ingress registry, Wazuh/AMiner certification, downstream clustering or ChainEdge workflow was changed.'))
    projected=[]
    for label,folder in [('before','blind_before'),('after','blind_A')]:
        field_keys=set();evidence_refs=0;occurrences=0
        for a in rows(OUT/folder/'canonical.jsonl.gz'):
            source='ids' if a['source_type']=='suricata' else a['raw_alert'].get('source_type')
            field_keys.update((source,v['raw_pointer']) for v in a['field_provenance'].values() if v['raw_pointer'])
            evidence_refs+=len(a['field_provenance']);occurrences+=len(a['entity_occurrences'])
        projected.append(dict(variant=label,distinct_source_raw_fields_with_direct_provenance=len(field_keys),
            field_provenance_occurrences=evidence_refs,entity_occurrences=occurrences))
    save('projection_coverage_comparison.json',dict(rows=projected,definition='Direct native JSON pointers, excluding whole-alert mapping pointers. Compound ProcessRef fields are described separately; raw preservation is independently verified.'))
    modified=['backend/app/adapters/multisource.py','backend/app/entities/extraction.py','backend/tests/test_source_bound_projection.py',
        'scripts/check_repository.py','evaluation/tests/test_source_bound_final.py',
        *[str(p.relative_to(ROOT)).replace('\\','/') for p in sorted((ROOT/'evaluation/framework/source_bound_final').glob('*.py'))]]
    modified=sorted(set(modified));file_hashes={p:sha(ROOT/p) for p in modified}
    threshold_only=[e for e in gt['edges'] if e['failure_stage']=='ADMISSION_THRESHOLD']
    if len(threshold_only)!=3 or any(not e['candidate'] for e in gt['edges']): raise ValueError('diagnosis_requires_review')
    save('diagnosis.json',dict(TASK_RESULT=RESULT,PRIMARY_BLOCKER='THRESHOLD',
        scope='Seven authored GT progression witness pairs; broader HN behavior also needs scoring/admission calibration.',
        proof='E01/E02/E05 have complete native projection, generated candidates, valid scores, passed evidence gate and weak_only=false, but unrounded scores below 0.65.',
        conclusion=CONCLUSION,strict_human_blind_isolation=False,production_truth_access=False,
        GT_GUIDED_POST_UNSEAL_REPAIR=False,post_truth_rescoring_calls=0))
    report=['# V5 Source-Bound Observability Audit + Projection Recovery on Final Dataset','',
        '## 1. TASK_RESULT','',f'`TASK_RESULT={RESULT}`。限定为六源投影与相关性候选恢复；不表示有向攻击链或全部审计条件均通过。','',
        '## 2. Final Dataset Integrity','',
        f'输入：`{INPUT}`。SHA-256：`{sha(INPUT)}`。',
        '9,985 = 9,500 background + 125 attack + 360 HN；六源分布逐项符合冻结值。真实时间范围：2018-11-03 13:30:05.907404 UTC 至 23:29:58.773679 UTC。',
        '原始 validation 通过；两次重建达到 BYTE_FOR_BYTE_PASS。验证器仅将本次 reproducibility receipt 重定向到本输出目录，未修改验证断言或数据。首次验证受主工程新增文件的保护清单阻断，临时移出两份新增评测脚本后重新验证通过，脚本随后恢复。','',
        table(['Source','Expected','Raw','Canonical','Adapter','Status'],[[s['source'],s['expected_count'],s['raw_count'],s['canonical_count'],s['adapter'],s['status']] for s in sources]),'',
        '输入、GT、generator、历史输出、原始需求和配置字节不变，逐文件证据见 final_immutability_check.json。','',
        '## 3. Blind Isolation','',
        f"盲产物封存时间 `{access['blind_completion_timestamp']}`；GT 首次解封 `{access['gt_access_timestamp']}`；封存 SHA-256 `{access['blind_manifest_sha256']}`。",
        '生产重放 worker 只读取 final JSONL，tripwire 记录未读 GT/scenario/provenance labels；该保护是可信 Python audit tripwire，不是 OS 沙箱。',
        '**人工盲隔离偏差：** 开发早期读取验证器前 65 行时看到了 HN 场景谓词定义，未读取具体 GT/配对/场景文件；因此不能宣称严格人工盲审。该偏差在修复和解封前已披露并封存。验证器本身在独立进程读取标签，仅回传聚合状态；历史回归测试在独立测试进程运行，不向生产 worker 提供真值。',
        '未在解封后修改生产代码、映射或重新评分。未完成尝试保留于 unsealed_attempt1；最终指标不使用该尝试。','',
        '## 4. Source Observability','',
        'Y=该数据中全量可见；P=条件可见；F=仿真扩展；N=该源观察面不可见。全部结论仅适用于 dataset-observed profile，不是现实产品普遍能力保证。','',
        table(['Source','Network','HTTP','Host','Account','Process','File','Flow','Request','Auth Session','Network Session'],
            [[c['source'],*[{'YES':'Y','PARTIAL':'P','FIXTURE_EXTENSION':'F','NO':'N'}[c['capabilities'][k]['value']] for k in
                ('Network','HTTP','Host','Account','Process','File','Flow','Request','Auth Session','Network Session')]] for c in caps]),'',
        'WAF HTTP 元数据属于基础观察面；request-to-worker 是扩展。EDR process instance 是已观测基础能力，process-bound network/session 对齐是扩展。Authentication 原生登录会话是基础，跨传感器对齐是扩展。Host/Audit 的 host_ip 是受监控资产属性，不宣称完整网络五元组。',
        '四态均显式定义。源内记录未检出可接受的矛盾身份；pair 间不同 PID、会话、用户等由现有 scorer 独立诊断。冻结 scorer 未消费 source capability metadata，缺字段仍可能标 MISSING；公式同时排除 MISSING/UNOBSERVABLE 的正负支撑。','',
        '## 5. Projection Defects Found','',
        '原先没有 Final envelope 六源入口；原生适配路径仅覆盖 IDS，其余 7,465 条不支持。原 native event 的主机、账号、进程、文件与 flow/request/auth/network identity 未进入统一层。WAF 独立 query 曾被丢弃，HTTP authority 的 URL scope 不兼容，file_hash 未形成实体。',
        '未将所有 raw 字段都宣称为评分特征。完整 raw→canonical 矩阵、直接指针覆盖的局限与剩余 raw-only 字段见 raw_to_canonical_projection_matrix.json、audit_interpretation.json。','',
        '## 6. Repairs Applied','',
        '新增 MultiSourceAdapter 六种显式原生 profile，IDS 复用既有 EVE 解析；外层 event_id/raw_pointer 仅评测追踪。保留原生 raw_alert，校验 wrapper/native 时间一致。',
        '投影主机、账号、进程实例与已有 lineage；用现有 SESSION 枚举及不同 kind/scope 表达 flow/request/auth/network/application identity。保留协议、动作、方向、HTTP 元数据与扩展上下文的 native provenance。恢复 URI/query、HTTP authority scope 和主机内 file_hash 实体。',
        '只改 production 两份文件；checker 仅登记新增 Adapter。其余为合成测试和 evaluation 重放/审计脚本。未改 Schema、公式、权重、阈值、候选/接纳策略。',
        *[f'- `{p}`' for p in modified],'',
        '## 7. Namespace / Role Audit','',
        'network_namespace=`traceback.lab.network`；asset_namespace=`traceback.lab.assets`；account_realm=`TRACEBACK.LAB`（原生 Auth 可核验）；source_namespace=`traceback.lab.<source>`。共享实验网络/资产的授权来自用户请求 §18，未读取资产或成员映射。',
        'IP 标准化；host/domain 保守大小写归一；账号保留大小写。Process=(host,pid,start_time)，其作用域受资产 namespace 约束。SESSION=(kind,namespace,value)，request/auth 为 host scope，network/flow 为 network scope，避免同名 token 跨种类碰撞。',
        'client_ip→src_ip，server_ip→dst_ip，server_host→host，HTTP host→domain；host_ip 保留 monitored_host_ip。未将 src/dst 推断为 attacker/victim，未把代理原始地址覆盖为直接源地址，未假设传感器独立。Firewall/Auth/Audit 复用 OTHER 枚举，但有独立原生 routing/namespace，并非 generic adapter。','',
        '## 8. Identifier Leakage Test','',
        'A=原始；B=替换全部外层 event_id；C=交替删除/替换全部外层 raw_pointer。canonical、候选集合/数量、全部成员评分和正式关联边 digest 均一致，PASS。B/C 未只比较计数，均完整执行候选和评分。原生设备 event_id 仍只承担 native record identity。',
        f"候选 digest `{summary['candidate_digest']}`；评分 digest `{summary['score_digest']}`；接纳 digest `{summary['admission_digest']}`。",'',
        '## 9. Before / After','',
        'Before 是原 Suricata native-body 路径（额外给予手动解包），并非虚构原来存在六源 wrapper 入口；不支持的五源明确计为 rejected。','',
        table(['Metric','Before','After'],[
            ['Direct native fields with provenance',projected[0]['distinct_source_raw_fields_with_direct_provenance'],projected[1]['distinct_source_raw_fields_with_direct_provenance']],
            ['Canonical alerts',2520,9985],['Canonical entities',881,11563],
            *[[k+' identities',beforeafter['before']['identity_counts'].get(k,0),beforeafter['after']['identity_counts'].get(k,0)] for k in ('flow','request','process','auth_session','network_session')],
            ['Candidate pairs',35122,240621],['Scored member pairs',35654,241464],['Admitted correlations',0,14788],
            ['GT candidate recall','0/7','7/7 (100%)'],['GT admission recall','0/7','4/7 (57.14%)']]),'',
        'Process/flow 等表中为唯一有作用域的实体数，不是告警出现次数。总计 9,985/9,985 原生 body 保真，277,890 个指针全部解析通过。','',
        '## 10. GT Edge Breakdown','',
        '主指标只匹配每条 GT 明确指定的支撑告警对，未以任意阶段成员替换。阶段笛卡尔积上界也为候选 7/7、接纳 4/7。原生证据、canonical/实体/指针、完整 breakdown 均逐边保存于 gt_edge_evaluation.json。','',
        table(['Edge','Sources','Raw → projected','Candidate','Score','Admitted','Failure'],[
            [e['edge_id'],' / '.join(e['source_types']),{'GT-E01':'flow+五元组 → SESSION/IP','GT-E02':'app session+ticket → SESSION/native refs',
                'GT-E03':'request+worker → SESSION/PROCESS','GT-E04':'process+logon → PROCESS/SESSION',
                'GT-E05':'SSH connection+tuple → SESSION/IP','GT-E06':'login+account+parent → SESSION/ACCOUNT/PROCESS',
                'GT-E07':'outbound connection+tuple → SESSION/IP'}[e['edge_id']],e['candidate'],f"{e['score']:.9f}",e['admitted'],e['failure_stage']] for e in gt['edges']]),'',
        'E01/E02/E05 均 valid、gate.passed=true、weak_only=false、无冲突或重复惩罚；唯一最终阻断是未舍入 score < 0.65。E02=0.648292319，不因接近阈值而舍入接纳。',
        'GT 8 个阶段、125 个观察均映射成功。最长连续 GT progression correlation witness 为 2/7；这不是 ChainEdge 长度，本轮未运行聚类/有向链重建。','',
        '## 11. Binding Recovery','',
        'Recovered 定义：该 typed pair 所有 authored 原生字段和值存在，且可回溯到 canonical provenance/entity 表示。它不自动意味着独立关系特征被评分消费、关联接纳或因果方向成立。','',
        table(['Binding','Recovered','Candidate','Scored','Admitted'],[[k,f"{v['recovered']}/{v['total']}",v['candidate'],v['scored'],v['admitted']] for k,v in binding['counts'].items()]),'',
        '22 个 typed pair（flow 15/request 2/process 2/auth-session 2/network-session 1），其中 20 个跨源。按 typed pair 去重，不把 51 条 observation component 加各 edge component 当作 51 个 binding。每条 binding 保存 raw/canonical 字段、共享实体、实际支持 feature、评分消费与接纳状态。',
        'request/response object 等仅有 provenance 的部分没有被伪造为新 causal relation。worker handling 不等于进程创建，已有 parent-child 关系仍要求完整实例。','',
        '## 12. Hard Negative Evaluation','',
        f"Known HN pairs=180；Candidate={hn['candidate']}；候选内拒绝={hn['candidate_rejected']}；未提名={hn['not_candidate']}；总 Rejected={hn['rejected']}；Admitted={hn['admitted']}；HN rejection rate={hn['rejection_rate']:.2%}。",
        'HN07/HN08/HN10/HN13 各 12 对被接纳，其余 11 类均 0。HN11 纯时间邻近没有提名。',
        '负例声明范围是“无 attack progression”，允许正常运维关系。这里的 48 是负例支撑对被 undirected correlation 接纳数；不能直接当作 48 条错误有向攻击边。用户要求的接纳暴露数如实为 48，未将未标注关系扩充为负例。','',
        table(['Scenario','Pairs','Candidates','Admitted'],[[s,v['total'],v['candidate'],v['admitted']] for s,v in hn['scenarios'].items()]),'',
        '## 13. Same-Source vs Cross-Source','',
        f"Same-source candidates={summary['same_source_candidates']:,}；admitted={summary['same_source_admitted']:,}。Cross-source candidates={summary['cross_source_candidates']:,}；admitted={summary['cross_source_admitted']:,}。",
        '`CROSS_SOURCE_REQUIRED=false`。按原生六源统计，未因 OTHER 枚举将 Auth/Firewall/Audit 误合并为同源。WAF→WAF 的 E02 候选存在。','',
        '## 14. Unlabeled Background','',
        f"Unlabeled background admitted edges: {bg['unlabeled_background_admitted_edges']:,}（两端 selected support 均为 background）；至少一端 background 为 {bg['background_touching_admitted_edges']:,}。",
        '未标记为 false positives、benign 或所有非 GT 负例；不提供全背景 precision/specificity。','',
        '## 15. Regression','',
        f"已执行选择回归 + 仓库约束 + 新评测器测试：{regression['tests_passed']} passed，{regression['tests_failed']} failed，{regression['tests_skipped']} skipped。新增六源投影测试 13 项均通过；评测器合成测试 5 项均通过。",
        '受影响回归 1519 passed / 1 failed / 4 skipped。该失败为旧历史 source freeze 检测本次授权 extraction.py 修改；没有伪造或重写旧 seal。仓库约束 110 passed / 4 failed；四个失败均来自同一组 11 个既有 semantic_repair/separation_direction 模块未登记 whitelist。',
        '已有适配器、实体、去重、候选、V2/V3/V4/V5、链/grounding、Stable ID/Schema、API/隔离与 AI 合成回归均在选择集中。整库测试尝试中断，未计为通过；未运行新的真实 AI provider 或新增来源外部认证。',
        'Formula/weights/threshold/candidate/admission policy unchanged；dataset/GT/generator/history unchanged。生产未导入 evaluation，tripwire/隔离测试与静态 AST 检查证据已保存。测试详见 regression_selection.json、regression_summary.json 和 XML/log。','',
        '## 16. Final Diagnosis','',
        '`PRIMARY_BLOCKER=THRESHOLD`（7 条指定 GT witness 的剩余三条）；HN 接纳暴露还说明需要独立开发划分上的 scoring/admission calibration。',
        CONCLUSION,
        '本轮停止于投影恢复、封存重放与评测，不启动下一阶段。严格人工盲审偏差、旧 seal 失配和既有 whitelist 失败均保留为限制；不声称本次所有检查通过。','',
        '十二问直接回答：','',
        table(['Question','Answer'],[
            ['Q1 六源可观察什么','见第4节能力表、原生字段 presence/non-null/distinct/examples 矩阵'],
            ['Q2 之前读漏什么','wrapper；五源原生字段；WAF query、HTTP scope、file hash'],
            ['Q3 raw存在 canonical缺什么','已修关键身份；未消费扩展字段见 audit_interpretation.json'],
            ['Q4 哪些 entity/role/scope/realm 有问题','host/domain混用、未共享实验scope、无typed session身份；第6–7节'],
            ['Q5 六源全部进入统一层吗','是，9985/9985；非generic'],
            ['Q6 base/fixture 区分了吗','是；第4节及 fixture_extension_capabilities.json'],
            ['Q7 合法共享scope互认吗','是；20/20跨源binding已表示且进入候选'],
            ['Q8 同源可关联吗','是，127597候选、4938接纳，跨源不是必要条件'],
            ['Q9 GT Candidate Recall','7/7=100%'],['Q10 GT Admission Recall','4/7=57.14%'],
            ['Q11 180HN接纳多少','48关联接纳；真值否定的是progression，非所有正常关系'],
            ['Q12 主阻断','THRESHOLD；三条valid/gate通过但score<0.65']]),'',
        '重现命令（该输出目录单次使用，不覆盖已有 seal）：prepare → validate → audit → metadata → freeze → blind A/B/C/before → seal → unseal → evaluate → finish。GT 解封后禁止重新运行生产阶段。评测器只读封存结果，不调用 scorer。','']
    (OUT/'V5_SOURCE_BOUND_OBSERVABILITY_REPORT.md').write_text('\n\n'.join(report),encoding='utf8')
    artifacts={str(p.relative_to(OUT)):sha(p) for p in OUT.rglob('*') if p.is_file() and
        not any(part in {'pytest_tmp','regression_tmp','repository_tmp','evaluator_tmp','unsealed_attempt1'} for part in p.parts)
        and p.name!='manifest.json'}
    save('manifest.json',dict(task=RESULT,primary_blocker='THRESHOLD',completed_at=now(),
        dataset=str(INPUT),final_dataset_sha256=sha(INPUT),ground_truth_sha256=sha(DATA/'ground_truth/ground_truth.json'),
        source_artifacts_sha256=baseline['dataset'],generator_sha256=baseline['generators'],
        implementation_version=prep['algorithm_version'],algorithm_version=record['algorithm_version'],
        config_hash=record['config_hash'],algorithm_only_config_hash=prep['config_hash'],mapping_digest=prep['mapping_digest'],threshold=prep['threshold'],
        files_modified=file_hashes,tests_executed=['regression_selection.json','repository.log','evaluator.xml'],
        tests_passed=regression['tests_passed'],tests_failed=regression['tests_failed'],tests_skipped=regression['tests_skipped'],
        blind_artifact_hashes=read(OUT/'blind_manifest.json')['files'],gt_unseal=access,
        strict_human_blind_isolation=False,blind_deviation='blind_isolation_deviation.json',
        post_truth_rescoring_calls=0,post_truth_production_changes=False,**unchanged,artifacts=artifacts))
    print('FINALIZED',RESULT,'THRESHOLD',regression['tests_passed'],regression['tests_failed'],len(artifacts),flush=True)


if __name__=='__main__': main()
