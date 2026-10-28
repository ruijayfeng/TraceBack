import {reasonLabel, reasonMessageLabel, categoryLabel, severityLabel, entityLabel, componentLabel, relationLabel} from '../../lib/displayLabels';
import {api} from '../../api/client';
import {useResource} from '../../api/hooks';
import type {Breakdown, ChainEdge, ChainNode, Entity, EvidenceSelection, Reason} from '../../types/domain';
import {JsonView, Notice, StableId, Time} from '../common';
import {Button} from '../ui/button';

export function ReasonList({reasons}: {reasons: Reason[]}) {return <ul className="reason-list">{reasons.map(r => <li key={r.reason_id}><b>{reasonLabel(r.code)}</b> · {reasonMessageLabel(r.message,r.code)}<details className="subtle-details"><summary>核验参数与引用</summary><JsonView value={r}/></details></li>)}</ul>;}

export function NodeDetail({node, entities, onEvidence}: {node: ChainNode; entities: Entity[]; onEvidence: (e: EvidenceSelection) => void}) {
  return <div className="object-detail"><h3>节点详情 · 算法构造依据</h3><p className="mono muted-text">{node.node_id}</p>
    <dl className="facts">
      <div className="fact"><dt>步骤类别</dt><dd>{categoryLabel(node.category)}</dd></div>
      <div className="fact"><dt>观察区间</dt><dd><Time value={node.start_time}/><Time value={node.end_time}/></dd></div>
      <div className="fact"><dt>置信分</dt><dd>{node.confidence}（算法分）</dd></div>
      <div className="fact"><dt>设备观测等级</dt><dd>{severityLabel(node.severity)}</dd></div>
    </dl>
    <h4>为什么存在这个节点</h4><ReasonList reasons={node.reasons}/>
    <h4>实体</h4>{entities.filter(e => node.entity_ids.includes(e.entity_id)).map(e => <p className="entity-line" key={e.entity_id}><b>{entityLabel(e.type)}</b> {e.display_value ?? e.value}</p>)}
    <Button className="mt-2" onClick={() => onEvidence({title: '节点支撑证据', objectId: node.node_id, alertIds: node.alert_ids})} size="sm" type="button">查看节点证据 · {node.alert_ids.length} 告警</Button>
    <details className="subtle-details"><summary>成员告警</summary>{node.alert_ids.map(a => <button className="text-action" onClick={() => onEvidence({title: '节点成员告警', objectId: node.node_id, alertIds: [a]})} key={a} type="button"><StableId copy={false} label="告警 ID" value={a}/></button>)}</details>
  </div>;
}

export function EdgeDetailPanel({analysisId, edge, onEvidence, onNode}: {analysisId: string; edge: ChainEdge; onEvidence: (e: EvidenceSelection) => void; onNode: (id: string) => void}) {
  const resource = useResource(signal => api.edge(analysisId, edge.edge_id, signal), [analysisId, edge.edge_id]);
  const detail = resource.data;
  return <div className="object-detail"><h3>边详情 · 已验证方向关系</h3><p className="mono muted-text">{edge.edge_id}</p><p>{relationLabel(edge.relation_type)}</p>
    <div className="direction"><button onClick={() => onNode(edge.source_node_id)} type="button"><StableId copy={false} label="源节点 ID" value={edge.source_node_id}/></button><strong>→</strong><button onClick={() => onNode(edge.target_node_id)} type="button"><StableId copy={false} label="目标节点 ID" value={edge.target_node_id}/></button></div>
    <p>方向评分 {edge.direction_score} · 置信度 {edge.confidence}</p>
    <h4>为什么连接与指向</h4><ReasonList reasons={edge.reasons}/>
    <h4>关联评分拆解</h4><div aria-label="关联评分拆解" className="table-frame" role="region" tabIndex={0}><table className="data-table"><thead><tr><th>评分项</th><th>原值</th><th>权重</th><th>贡献</th></tr></thead><tbody>{(['time','entity','relation','behavior','source','conflict','duplicate'] as const).map(key => <tr key={key}><td>{componentLabel(key)}</td><td className="num">{edge.score_breakdown[`${key}${key === 'conflict' || key === 'duplicate' ? '_penalty' : '_score'}` as keyof Breakdown] as number}</td><td className="num">{edge.score_breakdown.weights[key]}</td><td className="num">{edge.score_breakdown.contributions[key]}</td></tr>)}</tbody></table></div>
    <p>加权总分 {edge.score_breakdown.raw_total} · 最终评分 {edge.score_breakdown.final_score}</p><p>来源独立性：{relationLabel(edge.score_breakdown.source_independence)}</p>
    {resource.loading && <Notice kind="loading">正在读取支撑关联…</Notice>}
    {resource.error && <Notice kind="error">支撑关联不可读取：{resource.error}</Notice>}
    {detail && detail.analysis_id === analysisId && <><h4>实际支撑告警对</h4>{detail.correlation_edges.map(c => <div key={c.edge_id} className="support-pair"><p><StableId value={c.edge_id}/>{c.edge_id === edge.score_breakdown.selected_correlation_edge_id && <span className="pill pill-accent">选定支撑</span>}</p><p><StableId value={c.support_pair.alert_id_src}/> + <StableId value={c.support_pair.alert_id_dst}/></p><Button onClick={() => onEvidence({title: '边的支撑告警对', objectId: edge.edge_id, alertIds: [c.support_pair.alert_id_src, c.support_pair.alert_id_dst], pointers: c.reasons.flatMap(r => Array.isArray(r.params.raw_pointers) ? r.params.raw_pointers as unknown as import('../../types/domain').EvidencePointer[] : [])})} size="xs" type="button" variant="outline">查看边证据与字段指针</Button></div>)}</>}
    <details className="subtle-details"><summary>完整评分 / 配置引用</summary><JsonView value={edge.score_breakdown}/></details>
  </div>;
}
