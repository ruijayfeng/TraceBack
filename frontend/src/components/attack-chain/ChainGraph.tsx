import {categoryLabel, relationLabel} from '../../lib/displayLabels';
import {useId, useState} from 'react';
import type {Chain, ChainNode, Entity} from '../../types/domain';
import {Notice, shortId} from '../common';

export type Selection = {kind: 'node' | 'edge'; id: string} | null;
export function ChainGraph({chain, entities, selection, onSelect}: {chain: Chain; entities: Entity[]; selection: Selection; onSelect: (s: Selection) => void}) {
  const marker = useId().replace(/:/g, '');
  const [zoom, setZoom] = useState(1);
  // Coordinates are display only. Existing source/target IDs define every arrow.
  const nodes = [...chain.nodes].sort((a, b) => a.start_time.localeCompare(b.start_time) || a.node_id.localeCompare(b.node_id));
  const positions = new Map(nodes.map((node, index) => [node.node_id, {x: 24 + (index % 3)*300, y: 42 + Math.floor(index/3)*178}]));
  const width = Math.max(310, Math.min(nodes.length, 3)*300 + 24), height = Math.max(210, Math.ceil(nodes.length/3)*178 + 50);
  const label = (node: ChainNode) => node.entity_ids.map(i => entities.find(e => e.entity_id === i)?.display_value ?? entities.find(e => e.entity_id === i)?.value).filter(Boolean).slice(0, 2).join(' · ');
  const keyboard = (e: React.KeyboardEvent, s: Selection) => {if (e.key === 'Enter' || e.key === ' ') {e.preventDefault(); onSelect(s);}};
  return <div><div className="graph-toolbar"><span className="muted">{nodes.length} 节点 · {chain.edges.length} 有向边 · 置信分为算法分</span><button aria-label="缩小攻击链" onClick={() => setZoom(z => Math.max(.5, z-.25))}>−</button><button aria-label="重置攻击链缩放" onClick={() => setZoom(1)}>{Math.round(zoom*100)}%</button><button aria-label="放大攻击链" onClick={() => setZoom(z => Math.min(2, z+.25))}>+</button></div>
    {!nodes.length ? <Notice>当前快照没有可展示节点。</Notice> : <div className="graph-scroll"><svg className="chain-graph" aria-label="生产攻击链图" width={width*zoom} height={height*zoom} viewBox={`0 0 ${width} ${height}`}>
      <defs><marker id={marker} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="9" markerHeight="9" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#296b8f"/></marker></defs>
      {([...chain.edges].sort((a, b) => a.edge_id.localeCompare(b.edge_id))).map(edge => {
        const s = positions.get(edge.source_node_id), t = positions.get(edge.target_node_id);
        if (!s || !t) return null;
        const forward = t.x > s.x, sameRow = t.y === s.y;
        const sx = s.x + (sameRow ? (forward ? 264 : 0) : 132), sy = s.y + (sameRow ? 58 : (t.y > s.y ? 116 : 0));
        const tx = t.x + (sameRow ? (forward ? 0 : 264) : 132), ty = t.y + (sameRow ? 58 : (t.y > s.y ? 0 : 116));
        const d = sameRow ? `M ${sx} ${sy} C ${(sx+tx)/2} ${sy-28}, ${(sx+tx)/2} ${ty-28}, ${tx} ${ty}` : `M ${sx} ${sy} C ${sx} ${(sy+ty)/2}, ${tx} ${(sy+ty)/2}, ${tx} ${ty}`;
        const selected = selection?.kind === 'edge' && selection.id === edge.edge_id;
        return <g key={edge.edge_id} role="button" tabIndex={0} aria-label={`选择边 ${relationLabel(edge.relation_type)} ${shortId(edge.edge_id)}`} onClick={() => onSelect({kind: 'edge', id: edge.edge_id})} onKeyDown={e => keyboard(e, {kind: 'edge', id: edge.edge_id})} data-source={edge.source_node_id} data-target={edge.target_node_id} className={selected ? 'graph-edge selected' : 'graph-edge'}>
          <title>{edge.source_node_id} → {edge.target_node_id} · {relationLabel(edge.relation_type)}</title><path d={d} fill="none" className="edge-hit"/><path d={d} fill="none" className="edge-line" markerEnd={`url(#${marker})`}/><text x={(sx+tx)/2} y={(sy+ty)/2-12} textAnchor="middle" className="edge-label">{relationLabel(edge.relation_type)}</text></g>;
      })}
      {nodes.map(node => {const p = positions.get(node.node_id)!; return <g key={node.node_id} transform={`translate(${p.x},${p.y})`} role="button" tabIndex={0} aria-label={`选择节点 ${categoryLabel(node.category)} ${shortId(node.node_id)}`} onClick={() => onSelect({kind: 'node', id: node.node_id})} onKeyDown={e => keyboard(e, {kind: 'node', id: node.node_id})} className={selection?.id === node.node_id ? 'graph-node selected' : 'graph-node'}>
        <title>{node.node_id} · {label(node)}</title><rect width="264" height="116" rx="10"/><text x="16" y="27" className="node-category">{categoryLabel(node.category)}</text><text x="16" y="49">{(label(node) || '未抽取关键实体').slice(0, 32)}</text><text x="16" y="72">{node.start_time.slice(11, 23)} UTC</text><text x="16" y="95">{node.alert_ids.length} 告警 · 置信度 {node.confidence.toFixed(2)}</text></g>;})}
    </svg></div>}
    {chain.edges.length === 0 && <Notice kind="info">未重构出已验证的传播边。{nodes.length === 1 ? '单节点仍可查看告警、证据和研判。' : '节点保持独立展示。'}</Notice>}
    {chain.status === 'partial' && <Notice kind="info">部分链：存在未确定方向或被拒绝的关联。</Notice>}
    {chain.unresolved_correlation_edge_ids.length > 0 && <details><summary>未定向关联（{chain.unresolved_correlation_edge_ids.length}）</summary>{chain.unresolved_correlation_edge_ids.map(id => <p key={id}><code>{id}</code></p>)}</details>}
    {chain.edges.length > 0 && <div className="edge-navigation" aria-label="攻击链边列表">{chain.edges.map(e => <button key={e.edge_id} onClick={() => onSelect({kind: 'edge', id: e.edge_id})}>{shortId(e.source_node_id)} → {shortId(e.target_node_id)} · {relationLabel(e.relation_type)}</button>)}</div>}
  </div>;
}
