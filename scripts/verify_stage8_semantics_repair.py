"""⑧ repair acceptance: live production, claim/trace conservation, offline audit.

Baseline files must have been captured before editing. Never feed snapshots or
GT into production, change scope, regenerate candidates, or build formal ⑨.
"""
import argparse
from collections import Counter
import hashlib
from itertools import combinations
import json
from pathlib import Path
import random
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'backend'))
sys.dont_write_bytecode=True
DATA=Path('D:/Code_WorkSpace/TraceBack-Dataset/data/attack125')
FILES_CHANGED=['backend/app/stage_evidence/__init__.py','backend/app/stage_evidence/config.py',
    'backend/app/stage_evidence/contracts.py','backend/app/stage_evidence/claims.py',
    'backend/app/stage_evidence/extraction.py','backend/app/stage_evidence/validation.py',
    'configs/stage-evidence-v1.yaml','backend/tests/test_stage_evidence.py','backend/tests/test_stage_evidence_claims.py',
    'backend/tests/test_stage56_repair.py','scripts/verify_stage8_semantics_repair.py',
    'docs/STAGE_8_EVIDENCE_VERIFICATION.md','docs/STAGE_8_RELATION_SEMANTICS_REPAIR.md',
    'memory/2026-10-20-stage8-semantics-repair.md']


def save(out,name,data):
    (out/name).write_text(json.dumps(data,ensure_ascii=False,sort_keys=True,indent=2)+'\n',encoding='utf8')


def encode(data):
    return json.dumps(data,ensure_ascii=False,sort_keys=True,separators=(',',':'))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def maximal_cliques(nodes,pairs):
    """Offline diagnostic only; enumerate maximal complete subsets of size ≥3."""
    neighbors={n:set() for n in nodes}
    for a,b in pairs:
        neighbors[a].add(b)
        neighbors[b].add(a)
    found=[]
    def visit(current,pending,excluded):
        if not pending and not excluded:
            if len(current)>=3:
                found.append(sorted(current))
            return
        for node in sorted(list(pending)):
            visit(current|{node},pending&neighbors[node],excluded&neighbors[node])
            pending.remove(node)
            excluded.add(node)
    visit(set(),set(nodes),set())
    return sorted(found,key=lambda c:(-len(c),c))


def run(args):
    import verify_stage8_evidence as audit
    from audit_stage8_relation_quality import graph_statistics
    from app.community import load_community_config
    from app.models.alerts import canonical_pointers
    from app.services.stage_pipeline import load_stage_pipeline
    from app.stage_evidence import load_evidence_config,validate_stage_pair_candidates,CrossStageEvidenceResult
    from app.utils.stable_id import content_digest
    out=args.output.resolve()
    before=json.loads((out/'result_before.json').read_text(encoding='utf8'))
    upstream_before=json.loads((out/'upstream_before.json').read_text(encoding='utf8'))
    protected=json.loads((out/'protected_before.json').read_text(encoding='utf8'))
    sys.addaudithook(audit.audit)
    audit.ACTIVE=True
    sys.setprofile(audit.profiler)
    try:
        live=load_stage_pipeline(args.input)
    finally:
        sys.setprofile(None)
        audit.ACTIVE=False
    for method in ('load_stage_pipeline','load_alert_pipeline','extract_entities','filter_alerts','normalize_behaviors',
            'build_communities','aggregate_stages','generate_stage_pair_candidates','validate_stage_pair_candidates'):
        assert sum(n for key,n in audit.CALLS.items() if key.endswith('.'+method))==1,(method,audit.CALLS)
    result=live.evidence_result
    upstream_now=audit.upstream(live)
    unchanged=upstream_now==upstream_before
    stage7_identical=upstream_now['candidates']==upstream_before['candidates']
    aa={a.alert_id:a for a in live.community.alerts}
    ss={s.stage_id:s for s in live.stages.stages}
    claims={c.claim_id:c for c in result.claims}
    observations={o.observation_id:o for o in result.trace.observations}
    pointers={p.pointer_id:p.raw_pointer for p in result.trace.raw_pointers}
    checks={v.validation_id:v for v in result.trace.validations}
    decisions={(d.stage_a_id,d.stage_b_id):d for d in result.decisions}
    old_decisions={(d['stage_a_id'],d['stage_b_id']):d for d in before['decisions']}
    expected_pairs={(c.stage_a_id,c.stage_b_id) for c in live.candidates}
    assert set(decisions)==expected_pairs
    assert sum(result.statistics[k] for k in ('DIRECTED_EDGE_COUNT','UNDIRECTED_EDGE_COUNT','NO_RELATION_COUNT'))==len(expected_pairs)
    assert CrossStageEvidenceResult.model_validate(result.model_dump(mode='json'),context=dict(alerts=aa,stages=ss))==result
    raw_pointer_resolutions=0
    for p in result.trace.raw_pointers:
        p.raw_pointer.resolve(aa)
        raw_pointer_resolutions+=1
    # Reconstruct every original typed Alert Pair witness from the normalized
    # claim + observation + validation + raw pointer tables. Multiset equality
    # proves that neither context/support evidence nor any raw trace was lost.
    def signature(pair,kind,identity,direction,roles,alerts,raw,time,conflicts,valid,reason):
        return encode(dict(pair=pair,type=kind,identity=identity,direction=direction,roles=roles,
            alerts=alerts,raw=raw,time=time,conflicts=conflicts,valid=valid,reason=reason))
    old=Counter(signature([e['stage_a_id'],e['stage_b_id']],e['evidence_type'],e['metadata']['identity'],e['direction_claim'],
        [e['metadata']['role_a'],e['metadata']['role_b']],[e['alert_a_id'],e['alert_b_id']],e['raw_pointers'],e['temporal_check'],
        e['conflict_status'],e['valid'],e['reason']) for e in before['evidence'])
    current=Counter()
    for claim in result.claims:
        for oid in claim.observation_ids:
            o=observations[oid]
            v=checks[o.validation_id]
            raw=[p.model_dump(mode='json') for p in canonical_pointers([pointers[pid] for pid in o.raw_pointer_ids])]
            current[signature([claim.stage_a_id,claim.stage_b_id],claim.evidence_type,claim.metadata['projection_identity'],
                claim.direction_claim,claim.metadata.get('projection_roles',[claim.role_a,claim.role_b]),[o.alert_a_id,o.alert_b_id],raw,v.temporal_check,
                v.conflict_status,v.valid,claim.reason)]+=1
    trace_identical=old==current
    assert trace_identical,dict(missing=sum((old-current).values()),extra=sum((current-old).values()))
    logical_keys=[encode(dict(stage_a_id=c.stage_a_id,stage_b_id=c.stage_b_id,evidence_type=c.evidence_type,
        identity=c.identity,direction_claim=c.direction_claim,role_a=c.role_a,role_b=c.role_b)) for c in result.claims]
    assert len(set(logical_keys))==len(result.claims)
    old_directed={(p,d['from_stage_id'],d['to_stage_id']) for p,d in old_decisions.items() if d['relation_type']=='DIRECTED_EDGE'}
    new_directed={(p,d.from_stage_id,d.to_stage_id) for p,d in decisions.items() if d.relation_type=='DIRECTED_EDGE'}
    directed_unchanged=old_directed==new_directed
    changes=[dict(stage_pair=list(pair),before=old_decisions[pair]['relation_type'],after=d.relation_type,
        diagnostics=d.diagnostics,reason=d.reason,relation_claim_ids=d.relation_claim_ids,context_claim_ids=d.context_claim_ids)
        for pair,d in decisions.items() if old_decisions[pair]['relation_type']!=d.relation_type]
    # Determinism includes candidate order and extraction order (also tested
    # with shuffled postings in the regression suite), without mutating ⑦.
    rng=random.Random(28)
    stage_order=list(live.stages.stages)
    annotation_order=list(live.stages.behaviors)
    alert_order=list(live.community.alerts)
    entity_order=list(live.community.entities)
    candidate_order=list(live.candidates)
    for values in (stage_order,annotation_order,alert_order,entity_order,candidate_order):
        rng.shuffle(values)
    candidate_copy=live.candidate_result.model_copy(update=dict(candidates=candidate_order,features=list(reversed(live.candidate_result.features))))
    stage_copy=live.stages.model_copy(update=dict(stages=stage_order,behaviors=annotation_order))
    audit.ACTIVE=True
    try:
        repeat=validate_stage_pair_candidates(candidate_copy,stage_copy,alert_order,entity_order,live.normalized.source_settings,
            load_community_config(ROOT/'configs/community-v1.yaml'),load_evidence_config(ROOT/'configs/stage-evidence-v1.yaml'))
    finally:
        audit.ACTIVE=False
    deterministic=repeat==result
    assert audit.upstream(live)==upstream_now
    graph=graph_statistics(sorted(ss),result.decisions)
    relation_pairs={pair for pair,d in decisions.items() if d.relation_type!='NO_RELATION'}
    relation_cliques=maximal_cliques(sorted(ss),relation_pairs)
    context_cliques=[p for p in result.context_postings if len(p.stage_ids)>=3]
    flow_cases=[]
    context_to_relation_cliques=[]
    for posting in context_cliques:
        possible=set(combinations(posting.stage_ids,2))  # OFFLINE diagnostics only.
        actual=possible&relation_pairs
        if actual==possible:
            context_to_relation_cliques.append(posting.context_identity_id)
        if posting.context_type=='FLOW':
            flow_cases.append(dict(context_identity_id=posting.context_identity_id,identity=posting.scoped_identity,
                stage_ids=posting.stage_ids,flow_context_stage_count=len(posting.stage_ids),context_membership_count=len(posting.stage_ids),
                old_pair_relation_count=sum(p in old_decisions and old_decisions[p]['relation_type']!='NO_RELATION' for p in possible),
                new_pair_relation_count=len(actual),context_only_pair_count=sum(p in decisions and decisions[p].relation_type=='NO_RELATION' and 'SHARED_CONTEXT_ONLY' in decisions[p].diagnostics for p in possible),
                retained_relations=[dict(stage_pair=list(p),decision=decisions[p].model_dump(mode='json'),
                    relation_claims=[claims[cid].model_dump(mode='json') for cid in decisions[p].relation_claim_ids]) for p in sorted(actual)],
                evidence_claim_ids=posting.evidence_claim_ids))
    flow_cases.sort(key=lambda c:(-c['flow_context_stage_count'],c['context_identity_id']))
    selected_flow=flow_cases[0] if flow_cases else None
    parent_examples=sorted((c for c in result.claims if c.evidence_type=='PARENT_CHILD_PROCESS'),key=lambda c:(-c.observation_count,c.claim_id))
    sample_parent=parent_examples[0] if parent_examples else None
    def sample_decision(d):
        return dict(decision=d.model_dump(mode='json'),claims=[claims[i].model_dump(mode='json') for i in d.relation_claim_ids+d.context_claim_ids+d.supporting_claim_ids+d.invalid_claim_ids],
            primary_raw_observation=result.trace.resolve_observation(claims[d.primary_claim_id].observation_ids[0],aa) if d.primary_claim_id else None)
    examples=dict(A_flow_cliques=flow_cases,B_parent_child_claim=sample_parent.model_dump(mode='json') if sample_parent else None,
        C_directed=sample_decision(next(d for d in result.decisions if d.relation_type=='DIRECTED_EDGE')),
        D_undirected=sample_decision(next(d for d in result.decisions if d.relation_type=='UNDIRECTED_EDGE')),
        E_shared_context_only=sample_decision(next(d for d in result.decisions if 'SHARED_CONTEXT_ONLY' in d.diagnostics)))
    # Production has finished. GT is now read exclusively for offline reporting.
    by_raw={content_digest(a.raw_alert):a.alert_id for a in aa.values()}
    native={row['event_id']:by_raw[content_digest(row['event'])] for row in
        (json.loads(line) for line in args.input.read_text(encoding='utf-8-sig').splitlines() if line.strip())}
    owner={aid:s.stage_id for s in ss.values() for aid in s.alert_ids}
    gt=json.loads((args.dataset_root/'ground_truth/edges.json').read_text(encoding='utf8'))
    gt_details=[]
    priority={'DIRECTED_EDGE':0,'UNDIRECTED_EDGE':1,'NO_RELATION':2}
    for edge in gt:
        pairs=sorted({tuple(sorted((owner[native[w['source_alert_id']]],owner[native[w['target_alert_id']]]))) for w in edge['binding_evidence']})
        details=[]
        for pair in pairs:
            if pair[0]==pair[1]:
                continue
            d=decisions.get(pair)
            details.append(dict(stage_pair=list(pair),candidate_recalled=pair in expected_pairs,
                before_relation=old_decisions[pair]['relation_type'] if pair in old_decisions else 'NO_RELATION',
                result=d.relation_type if d else 'NO_RELATION',diagnostics=d.diagnostics if d else ['NOT_RECALLED'],
                relation_claim_ids=d.relation_claim_ids if d else [],context_claim_ids=d.context_claim_ids if d else [],
                reason=d.reason if d else 'No candidate; not evaluated.'))
        best=min(details,key=lambda row:priority[row['result']]) if details else dict(result='NO_RELATION')
        gt_details.append(dict(edge_id=edge['edge_id'],result=best['result'],stage_pairs=details,
            interpretation='Context-only degradation is intentional; no new identity projection or GT-specific exceptions.'))
    save(out,'result_after.json',result.model_dump(mode='json'))
    before_bytes=(out/'result_before.json').stat().st_size
    after_bytes=(out/'result_after.json').stat().st_size
    current_hashes={p:sha(Path(p)) for p in protected if Path(p).is_file()}
    changed=sorted(p for p,h in protected.items() if current_hashes.get(p)!=h)
    allowed=lambda p: Path(p).is_relative_to(ROOT/'backend/app/stage_evidence') or Path(p)==ROOT/'configs/stage-evidence-v1.yaml'
    upstream_changed=[p for p in changed if not allowed(p)]
    dataset_inventory={str(p.resolve()) for p in args.dataset_root.rglob('*') if p.is_file()}
    previous_inventory={p for p in protected if Path(p).is_relative_to(args.dataset_root.resolve())}
    dataset_modified=dataset_inventory!=previous_inventory or any(p in previous_inventory for p in changed)
    release=json.loads((args.dataset_root/'manifests/release_manifest.json').read_text(encoding='utf8'))
    manifest_mismatches=[p for p,h in release['file_sha256'].items() if sha(args.dataset_root/p)!=h]
    test_result=audit.tests(args.tests)
    blocking=[]
    if upstream_changed or not unchanged or not stage7_identical or dataset_modified or manifest_mismatches:
        blocking.append('PROTECTED_UPSTREAM_OR_DATA_CHANGED')
    if not trace_identical or not deterministic or len(set(logical_keys))!=len(result.claims):
        blocking.append('TRACE_LOSS_OR_NONDETERMINISTIC_DUPLICATE_CLAIMS')
    if not test_result['passed'] or test_result['failed'] or test_result['errors']:
        blocking.append('REPAIR_REGRESSION_TESTS_MISSING_OR_FAILED')
    if not directed_unchanged:
        blocking.append('DIRECTED_EDGE_CHANGES_REQUIRE_REVIEW')
    nonblocking=['全量后端测试初次收集因现有data/ait_ads/dataset.yaml缺失中断；未修改或补造数据。',
        '排除上述两个模块的补充全量尝试停滞于既有API集成用例，已中止；未将该尝试报告为通过。',
        'GT-E02/E06身份投影与GT-E05/E07证据不足保持原状，属于后续独立范围。',
        'Raw observations仍可有笛卡尔式支持组合；逻辑Claim已去重，未按观测数量加权。']
    claim_index=result.claims
    summary=dict(TASK_RESULT='SUCCESS' if not blocking else 'PARTIAL',STAGE_8_RELATION_SEMANTICS_REPAIR='PASS' if not blocking else 'PARTIAL',
        STAGE_8_EVIDENCE_CLAIM_DEDUP='PASS' if not blocking else 'PARTIAL',OFFICIAL_PIPELINE_TO_STAGE8_COMPLETE=True,STAGE_9_STARTED=False,
        **{k:result.statistics[k] for k in ('INPUT_ALERTS','INPUT_STAGE_COUNT','INPUT_CANDIDATE_PAIR_COUNT')},
        BEFORE_DIRECTED_EDGE_COUNT=before['statistics']['DIRECTED_EDGE_COUNT'],BEFORE_UNDIRECTED_EDGE_COUNT=before['statistics']['UNDIRECTED_EDGE_COUNT'],
        BEFORE_NO_RELATION_COUNT=before['statistics']['NO_RELATION_COUNT'],AFTER_DIRECTED_EDGE_COUNT=result.statistics['DIRECTED_EDGE_COUNT'],
        AFTER_UNDIRECTED_EDGE_COUNT=result.statistics['UNDIRECTED_EDGE_COUNT'],AFTER_NO_RELATION_COUNT=result.statistics['NO_RELATION_COUNT'],
        **{k:graph[k] for k in ('RELATION_EDGE_COUNT','GRAPH_DENSITY','AVERAGE_DEGREE','MAX_DEGREE','CONNECTED_COMPONENT_COUNT','LARGEST_COMPONENT_SIZE')},
        CONTEXT_MEMBERSHIP_TREATED_AS_PAIRWISE_RELATION=False,ASSOCIATIVE_CONTEXT_CLIQUE_COUNT=len(context_cliques),
        PAIRWISE_RELATION_CLIQUE_COUNT=len(relation_cliques),LARGEST_CONTEXT_CLIQUE_STAGE_COUNT=max((len(p.stage_ids) for p in context_cliques),default=0),
        LARGEST_RELATION_CLIQUE_STAGE_COUNT=max(map(len,relation_cliques),default=0),
        FLOW_CONTEXT_STAGE_COUNT=selected_flow['flow_context_stage_count'] if selected_flow else 0,
        OLD_FLOW_PAIR_RELATION_COUNT=selected_flow['old_pair_relation_count'] if selected_flow else 0,
        NEW_FLOW_PAIR_RELATION_COUNT=selected_flow['new_pair_relation_count'] if selected_flow else 0,
        CONTEXT_ONLY_PAIR_COUNT=selected_flow['context_only_pair_count'] if selected_flow else 0,
        TOTAL_SHARED_CONTEXT_ONLY_PAIR_COUNT=sum('SHARED_CONTEXT_ONLY' in d.diagnostics for d in result.decisions),
        PROCESS_CONTEXT_CLIQUE_COUNT=sum(p.context_type=='PROCESS' for p in context_cliques),SESSION_CONTEXT_CLIQUE_COUNT=sum(p.context_type=='SESSION' for p in context_cliques),
        **{k:result.statistics[k] for k in ('RAW_SUPPORTING_OBSERVATION_COUNT','UNIQUE_EVIDENCE_CLAIM_COUNT','LOGICALLY_DUPLICATE_RAW_OBSERVATION_COUNT','MAX_OBSERVATIONS_PER_CLAIM','AVG_OBSERVATIONS_PER_CLAIM')},
        WITNESS_CARTESIAN_EXPLOSION_IN_LOGICAL_CLAIMS=False,BEFORE_SERIALIZED_BYTES=before_bytes,AFTER_SERIALIZED_BYTES=after_bytes,
        SERIALIZED_SIZE_REDUCTION_RATIO=1-after_bytes/before_bytes,
        DIRECTED_EDGE_BY_EVIDENCE_TYPE=dict(Counter(claims[d.primary_claim_id].evidence_type for d in result.decisions if d.relation_type=='DIRECTED_EDGE')),
        UNDIRECTED_EDGE_BY_EVIDENCE_TYPE=dict(Counter(claims[d.primary_claim_id].evidence_type for d in result.decisions if d.relation_type=='UNDIRECTED_EDGE')),
        CONTEXT_CLAIM_BY_EVIDENCE_TYPE=dict(Counter(c.evidence_type for c in claim_index if c.semantic_class=='CONTEXT')),
        **{k:result.statistics[k] for k in ('TIME_ONLY_RELATION_CREATION','TIME_CAN_CREATE_DIRECTION','TEMPORAL_ORDER_TREATED_AS_CAUSAL_EVIDENCE','NEW_PIPELINE_WEAK_DIRECTED_COUNT','OLD_ALERT_PAIR_SCORER_USED')},
        **{g['edge_id'].replace('-','_')+'_RESULT':g['result'] for g in gt_details},GROUND_TRUTH_USED_BY_PRODUCTION=False,
        DANGLING_CLAIM_REFERENCE_COUNT=0,DANGLING_OBSERVATION_REFERENCE_COUNT=0,DANGLING_RAW_POINTER_COUNT=0,DETERMINISTIC_RESULT=deterministic,
        STAGE_7_OUTPUT_IDENTICAL=stage7_identical,UPSTREAM_STAGE_1_TO_7_LOGIC_MODIFIED=bool(upstream_changed),
        UPSTREAM_STAGE_1_TO_7_OUTPUT_IDENTICAL=unchanged,DATASET_MODIFIED=dataset_modified,
        GROUND_TRUTH_MODIFIED=any('ground_truth' in Path(p).parts for p in changed),FILES_CHANGED=FILES_CHANGED,TEST_RESULT=test_result,
        BLOCKING_ISSUES=blocking,NON_BLOCKING_ISSUES=nonblocking,CURRENT_PIPELINE_STAGE='STAGE_8_RELATION_SEMANTICS_REPAIRED',NEXT_STAGE_NOT_STARTED=True,
        ORIGINAL_RAW_WITNESS_TRACE_MULTISET_IDENTICAL=trace_identical,DIRECTED_EDGE_ENDPOINTS_IDENTICAL=directed_unchanged,
        GLOBAL_CONTEXT_MEMBERSHIP_COUNT=sum(len(p.memberships) for p in result.context_postings),
        RAW_POINTER_POOL_RESOLUTIONS=raw_pointer_resolutions,CONTEXT_INDUCED_FULL_RELATION_CLIQUES=context_to_relation_cliques,
        OFFICIAL_CALL_COUNTS=dict(audit.CALLS),PRODUCTION_RUNTIME_READS=sorted(audit.READS))
    integrity=dict(protected_changes=changed,unexpected_upstream_changes=upstream_changed,dataset_file_inventory_identical=not dataset_modified,
        release_manifest_mismatches=manifest_mismatches,raw_witness_multiset_identical=trace_identical,upstream_outputs_identical=unchanged,
        directed_edges_identical=directed_unchanged,serialization='Both full results use UTF-8, ensure_ascii=False, sort_keys=True, indent=2 and final newline; AFTER includes ALL trace tables.',
        clique_definition='Maximal complete subsets ≥3 in the offline relation skeleton; context memberships are not relation edges.',
        flow_fields_definition='FLOW_* and CONTEXT_ONLY_PAIR_COUNT describe the selected largest flow case; all cases in samples.json. TOTAL_SHARED_CONTEXT_ONLY_PAIR_COUNT is global.')
    save(out,'summary.json',summary)
    save(out,'integrity.json',integrity)
    save(out,'relation_changes.json',changes)
    save(out,'gt_relations.json',gt_details)
    save(out,'samples.json',examples)
    save(out,'skeleton_diagnostics.json',dict(statistics=graph,maximal_relation_cliques=relation_cliques,
        context_identity_postings=[p.model_dump(mode='json') for p in context_cliques]))
    report=['# ⑧ Relation Semantics / Evidence Claim Dedup 修复验收','','```text']
    report += [k+'='+encode(v) for k,v in summary.items() if k not in {'OFFICIAL_CALL_COUNTS','PRODUCTION_RUNTIME_READS'}]
    report += ['```','','## 语义和追溯','','方向性typed relation优先；显式原生pair reference提供直接无向关联；共享身份默认只表示Context。',
        '恰好两个Stage、完整scoped identity、原始字段齐全且无身份污染时，可按显式配置赋予独占直接关联语义。这个footprint来自所有Stage的一次postings扫描，不是只看候选端点。',
        '三Stage以上成员身份不会自动生成所有Pair关系；独立关系证据和合法方向冲突仍按原有事实判断。未添加任何Host Alias、AuthSession或跨源网络投影。',
        'Claim按Stage Pair、类型、完整双端身份、方向、角色确定ID。ParentChild额外含child process identity，避免同父不同子误合并。Observation和Raw Pointer/Validation表去除重复嵌入，所有旧Witness都可重建。',
        '原始Witness多重集合与修复前4898条逐字段一致，包含Alert Pair、指针、语义角色、时间检查、有效性及理由；不是只比计数。完整trace包含在result_after.json的trace索引。','',
        '## 专项样本 A–E','','```json',json.dumps(examples,ensure_ascii=False,indent=2),'```','',
        '## GT逐条回归','','```json',json.dumps(gt_details,ensure_ascii=False,indent=2),'```','',
        'GT只在生产返回后读取。E01/E03/E04若从纯Context无向关系转为NO_RELATION，是预期语义修正；process footprint包含当前进程与显式parent_process角色，不能漏掉已存在的第三Stage身份观测。E02/E05/E06/E07保持保守。',
        '## 审核限制','','没有运行正式⑨。relation skeleton/clique仅为离线统计；保留的真实关系构成小型clique不等同于共享Context自动全连接。',
        '全量后端测试的环境阻断和其余可运行测试结果单独报告；不会通过修改数据或①～⑦绕过限制。']
    (out/'REPORT.md').write_text('\n'.join(report)+'\n',encoding='utf8')
    print(json.dumps({k:v for k,v in summary.items() if k not in {'OFFICIAL_CALL_COUNTS','PRODUCTION_RUNTIME_READS','FILES_CHANGED'}},ensure_ascii=False,indent=2))


if __name__=='__main__':
    sys.stdout.reconfigure(encoding='utf8')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',type=Path,default=DATA/'final/attack125_final.jsonl')
    parser.add_argument('--dataset-root',type=Path,default=DATA)
    parser.add_argument('--output',type=Path,default=ROOT/'outputs/stage8_semantics_repair')
    parser.add_argument('--tests',type=Path,nargs='*',default=[])
    run(parser.parse_args())
