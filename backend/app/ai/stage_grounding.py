"""Ground Stage drafts against immutable membership, raw fields and witnesses.

No regular-expression 'hallucination detector' approves free factual prose.
Selections are checked structurally, scoped to a Stage/Relation, re-qualified
from raw values, and only then rendered. This is an independent publication
boundary; the existing Incident grounding module remains unchanged.
"""
from app.models.base import resolve_pointer
from .stage_context import VERSION
from .stage_knowledge import KNOWLEDGE, qualify, confirmed, render_fact, render_confirmed


def require(condition, code):
    if not condition:
        raise ValueError(code)


def unique_ids(items, key, expected, code):
    ids = [getattr(item, key) for item in items]
    require(len(ids) == len(set(ids)) and set(ids) == set(expected), code)


def selection_fact(selection, facts, alerts):
    require(selection.fact_id in facts, 'invalid_fact_reference')
    fact = facts[selection.fact_id]
    require(selection.evidence_refs == fact['evidence_refs'], 'invalid_alert_reference')
    for ref in fact['field_refs']:
        require(ref['alert_id'] in alerts, 'invalid_alert_reference')
        raw_value = resolve_pointer(alerts[ref['alert_id']]['raw_alert'], ref['pointer'])
        require(type(raw_value) == type(ref['value']) and raw_value == ref['value'], 'raw_field_mismatch')
    # Role values must themselves resolve, rather than being inferred from an
    # unrelated signature, category, filename, command argument or another alert.
    for ref in fact['roles'].values():
        require(ref in fact['field_refs'], 'unbound_role')
    return fact


def published_fact(fact, *, impact=False):
    return dict(fact_id=fact['fact_id'], description=render_confirmed(fact) if impact else render_fact(fact),
                evidence_refs=fact['evidence_refs'], field_refs=fact['field_refs'])


CLAIM_LABELS = {
    'SAME_PROCESS_INSTANCE': '两个阶段的证据引用同一进程实例',
    'PROCESS_PARENT_CHILD': '既有证据记录父子进程语义',
    'PARENT_CHILD_PROCESS': '既有证据记录父子进程语义',
    'AUTH_ESTABLISH_USE': '认证建立与会话使用属于同一认证上下文',
    'SAME_STRONG_SESSION': '两个阶段共享经过验证的会话标识及作用域',
    'SAME_SCOPED_FLOW': '两个阶段共享同一作用域内的流标识和网络元组',
    'SAME_HOST': '两个阶段具有已验证的主机上下文',
    'SAME_REQUEST': '两个阶段引用同一请求上下文',
    'SAME_SCOPED_REQUEST': '两个阶段引用同一作用域内的请求上下文',
    'REQUEST_PROCESS': '已有请求与进程关联证据',
    'REQUEST_PROCESS_BINDING': '已有请求与进程绑定证据',
    'SAME_CONNECTION': '两个阶段共享已验证的连接上下文',
    'NETWORK_CONNECTION': '已有网络连接关联证据',
    'SAME_TRUSTED_CONNECTION': '两个阶段共享可信来源、相同作用域中的原生连接标识',
    'CONNECTION_ESTABLISH_ACCEPT': '已有连接建立与接收语义证据',
    'OBJECT_HANDOFF': '已有请求对象生成与后续使用的交接证据',
    'SAME_SCOPED_OBJECT': '两个阶段引用同一作用域中的原生对象',
    'SAME_ACCOUNT': '两个阶段具有已验证的账户上下文',
    'SHARED_FILE_PATH': '两个阶段的原始字段共享文件路径；该字段本身不证明文件内容相同',
    'SHARED_PROCESS_DESCRIPTOR': '两个阶段共享进程描述字段；该字段本身不证明同一进程实例',
    'NETWORK_ENDPOINT_OVERLAP': '两个阶段存在网络端点上下文重叠',
    'FILE_PRODUCE_CONSUME': '已有文件生成与使用语义证据',
    'REQUEST_OBJECT_HANDOFF': '已有请求对象交接语义证据',
}


def is_temporal_only(relation, package):
    claims = [package['claims'][cid] for cid in relation['supporting_claim_ids']]
    types = {c['evidence_type'].upper() for c in claims}
    return relation['relation_type'] == 'WEAK_DIRECTED' or bool(types) and all(
        any(word in kind for word in ('TEMPORAL', 'TIME_PROXIMITY', 'TIME_ADJACENCY')) for kind in types)


def render_relation(selected, relation, package, alerts):
    for key in ('source_stage_id', 'target_stage_id', 'relation_type', 'direction_status'):
        require(getattr(selected, key) == relation[key], 'relation_or_direction_mutation')
    cids = selected.supporting_claim_ids
    require(len(cids) == len(set(cids)) and set(cids) <= set(relation['supporting_claim_ids']),
            'invalid_relation_evidence')
    require(set(relation['required_claim_ids']) <= set(cids), 'missing_primary_relation_evidence')
    supporting = []
    for cid in cids:
        claim = package['claims'][cid]
        require(claim['valid'] is True, 'invalid_relation_claim')
        require({claim['stage_a_id'], claim['stage_b_id']} == {
            relation['decision']['stage_a_id'], relation['decision']['stage_b_id']}, 'cross_relation_claim')
        refs, field_refs = set(), []
        for oid in claim.get('observation_ids', []):
            obs = package['observations'][oid]
            refs.update(a for a in (obs.get('alert_a_id'), obs.get('alert_b_id')) if a)
            for pid in obs.get('raw_pointer_ids', []):
                ptr = package['resolved_pointers'][pid]
                ref = ptr['raw_pointer']
                require(ref['alert_id'] in alerts, 'invalid_relation_alert_reference')
                require(ref['alert_id'] in refs, 'relation_pointer_outside_witness')
                raw_value = resolve_pointer(alerts[ref['alert_id']]['raw_alert'], ref['pointer'])
                require(raw_value == ptr['value'], 'relation_raw_field_mismatch')
                field_refs.append(dict(**ref, value=raw_value))
        require(refs and refs <= alerts.keys(), 'relation_witness_missing')
        kind = claim['evidence_type']
        label = CLAIM_LABELS.get(kind, '正式证据类型 ' + kind)
        supporting.append(dict(claim_id=cid, evidence_type=kind,
            description=label + '；算法证据说明：' + claim.get('reason', ''),
            evidence_refs=sorted(refs), field_refs=field_refs))
    unresolved = relation['direction_status'] == 'UNRESOLVED'
    temporal = is_temporal_only(relation, package)
    limitations = ['时间先后只作为背景，不能单独确认攻击因果关系。']
    omitted = sum(package['claims'][cid].get('omitted_observation_count', 0) for cid in cids)
    if omitted:
        limitations.append(f'此处展示逐条正式 Claim 的见证摘录，另有 {omitted} 条见证可通过原证据追溯接口回查。')
    if unresolved:
        explanation = '两个 Stage 存在正式算法接受的证据关联，但当前方向仍未解决；不表示其中一个阶段导致另一个阶段。'
        limitations.append('UNDIRECTED_EDGE 保持无向，不按时间顺序定向。')
    elif temporal:
        explanation = '正式算法保留了该关系及其观测顺序；当前只能确认时间上的先后，无法据此确认攻击因果关系。'
        limitations.append('仅有时间证据，不能据此确认因果或攻击步骤推进。')
    else:
        explanation = ('正式算法已接受 ' + relation['source_stage_id'] + ' → ' + relation['target_stage_id'] +
                       '；现有关系证据支持该方向，AI 仅解释上述证据，不重新判断方向。')
    return dict(**{k: relation[k] for k in ('relation_id', 'accepted', 'source_stage_id', 'target_stage_id',
                                           'relation_type', 'direction_status')},
        relation_explanation=explanation, supporting_evidence=supporting, limitations=limitations)


def topology(package):
    ids = package['chain']['stage_ids']
    outgoing, incoming, degree = ({sid: [] for sid in ids} for _ in range(3))
    undirected = []
    for relation in package['relations']:
        a, b = relation['source_stage_id'], relation['target_stage_id']
        degree[a].append(b)
        degree[b].append(a)
        if relation['direction_status'] == 'UNRESOLVED':
            undirected.append(relation['relation_id'])
        elif not is_temporal_only(relation, package):
            outgoing[a].append(b)
            incoming[b].append(a)
    branches = [dict(stage_id=sid, target_stage_ids=sorted(set(targets)))
                for sid, targets in outgoing.items() if len(set(targets)) > 1]
    merges = [dict(stage_id=sid, source_stage_ids=sorted(set(sources)))
              for sid, sources in incoming.items() if len(set(sources)) > 1]
    isolated = [sid for sid in ids if not degree[sid]]
    return dict(branches=branches, merges=merges, undirected_relation_ids=undirected,
                isolated_stage_ids=isolated, has_directed_cycle=package['chain']['has_directed_cycle'])


def validate_and_render(context, draft):
    package = context.data
    require(draft.chain_id == package['chain']['chain_id'], 'cross_chain_reference')
    stage_map = {s['stage']['stage_id']: s for s in package['stages']}
    relations = {r['relation_id']: r for r in package['relations']}
    unique_ids(draft.stages, 'stage_id', stage_map, 'stage_membership_mutation')
    unique_ids(draft.relations, 'relation_id', relations, 'relation_membership_mutation')
    result_stages, all_selected, all_confirmed, all_codes = [], {}, {}, set()
    all_alerts = {a['alert_id']: a for s in package['stages'] for a in s['alerts']}
    for selected in draft.stages:
        item = stage_map[selected.stage_id]
        facts = {f['fact_id']: f for f in item['facts']}
        alerts = {a['alert_id']: a for a in item['alerts']}
        observed = {}
        for selection in selected.observed_facts:
            require(selection.fact_id not in observed, 'duplicate_fact')
            fact = selection_fact(selection, facts, alerts)
            observed[fact['fact_id']] = fact
        interpretation = selected.behavior_interpretation
        require(set(interpretation.fact_ids) <= observed.keys(), 'ungrounded_interpretation')
        qualified = {c for f in observed.values() for c in qualify(f['roles'])}
        require(interpretation.code in qualified, 'unsupported_interpretation')
        if interpretation.code != 'insufficient':
            require(interpretation.fact_ids and all(interpretation.code in qualify(observed[fid]['roles'])
                for fid in interpretation.fact_ids), 'unsupported_interpretation')
        else:
            require(interpretation.confidence == 0, 'insufficient_evidence_confidence')
        require(len(selected.potential_impact_codes) == len(set(selected.potential_impact_codes)), 'duplicate_risk')
        require(set(selected.potential_impact_codes) <= qualified - {'insufficient'}, 'unsupported_potential_impact')
        impacts = []
        for selection in selected.confirmed_impact:
            fact = selection_fact(selection, facts, alerts)
            require(fact['fact_id'] in observed, 'unobserved_confirmed_impact')
            require(confirmed(fact['roles']) is not None, 'unconfirmed_impact')
            require(selection.fact_id not in all_confirmed, 'duplicate_confirmed_impact')
            impacts.append(published_fact(fact, impact=True))
            all_confirmed[fact['fact_id']] = fact
        interpretation_label, interpretation_text, _ = KNOWLEDGE[interpretation.code]
        if interpretation.code != 'insufficient':
            supporting = observed[interpretation.fact_ids[0]]
            interpretation_text += ' 本次依据：' + render_fact(supporting)
        all_selected.update(observed)
        all_codes.update(selected.potential_impact_codes)
        result_stages.append(dict(stage_id=selected.stage_id,
            observed_facts=[published_fact(f) for f in observed.values()],
            behavior_interpretation=dict(label=interpretation_label, description=interpretation_text,
                confidence=interpretation.confidence, confidence_scope='AI_EXPLANATION_ONLY',
                evidence_refs=sorted({aid for fid in interpretation.fact_ids for aid in observed[fid]['evidence_refs']})),
            missing_evidence=item['missing_evidence'],
            risk_analysis=dict(potential_impact=[KNOWLEDGE[c][2] for c in selected.potential_impact_codes],
                potential_impact_support=[dict(code=c, evidence_refs=sorted({aid for f in observed.values()
                    if c in qualify(f['roles']) for aid in f['evidence_refs']})) for c in selected.potential_impact_codes],
                confirmed_impact=impacts)))
    result_relations = [render_relation(r, relations[r.relation_id], package, all_alerts) for r in draft.relations]
    summary = draft.chain_summary
    require(len(summary.stage_ids) == len(set(summary.stage_ids)) and set(summary.stage_ids) == set(stage_map),
            'summary_stage_membership_mutation')
    require(set(summary.main_fact_ids) <= all_selected.keys(), 'summary_unsupported_fact')
    require(set(summary.confirmed_fact_ids) <= all_confirmed.keys(), 'summary_unconfirmed_impact')
    require(set(summary.potential_impact_codes) <= all_codes, 'summary_unsupported_potential_impact')
    shape = topology(package)
    notes = [f"当前 Chain 保留 {len(stage_map)} 个 Stage、{len(relations)} 条既有关系。"]
    if len(stage_map) == 1:
        notes.append('这是单节点 Chain，保留该孤立 Stage，没有跨阶段攻击路径。')
    if shape['branches'] or shape['merges']:
        notes.append(f"图结构包含 {len(shape['branches'])} 处出向分支、{len(shape['merges'])} 处汇聚，不能简单视为严格线性的攻击路径；分支节点之间不据此推断直接先后关系。")
    if shape['undirected_relation_ids']:
        notes.append(f"{len(shape['undirected_relation_ids'])} 条无向关系的方向仍未解决。")
    if shape['has_directed_cycle']:
        notes.append('已有有向环被保留，不能描述成严格先后步骤。')
    if shape['isolated_stage_ids'] and len(stage_map) > 1:
        notes.append('链中无关联连线的孤立 Stage 仍被完整保留。')
    notes.append(f"本次只解释当前 Chain；正式结果共 {package['independent_chain_count']} 条独立 Chain，未合并。")
    uncertainties = sorted({note for s in result_stages for note in s['missing_evidence']} |
                           {note for r in result_relations for note in r['limitations']})
    if shape['undirected_relation_ids']:
        uncertainties.append('存在无向边，方向仍未解决；不能依据时间推断方向。')
    return dict(contract_version=VERSION, chain_id=draft.chain_id, input_digest=context.input_digest,
        read_only=True, stages=result_stages, relations=result_relations,
        chain_summary=dict(title='基于现有证据的阶段行为与影响研判', summary=' '.join(notes),
            stage_ids=summary.stage_ids, topology=shape,
            main_observed_activities=[published_fact(all_selected[fid]) for fid in summary.main_fact_ids],
            potential_overall_impact=[KNOWLEDGE[c][2] for c in summary.potential_impact_codes],
            confirmed_overall_impact=[published_fact(all_confirmed[fid], impact=True) for fid in summary.confirmed_fact_ids],
            uncertainties=uncertainties),
        validated_selection=draft.model_dump(mode='json'))
