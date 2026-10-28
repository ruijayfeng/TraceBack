import {categoryLabel, relationLabel} from '../../lib/displayLabels';
import {Maximize2, Minus, Plus, RotateCcw} from 'lucide-react';
import {useEffect, useId, useMemo, useRef, useState} from 'react';
import type {Chain, ChainNode, Entity} from '../../types/domain';
import {useMediaQuery} from '../../lib/useMediaQuery';
import {Notice, shortId} from '../common';
import {TraceIcon} from '../ui/trace-icon';

export type Selection = {kind: 'node' | 'edge'; id: string} | null;

const NODE_WIDTH = 264;
const NODE_HEIGHT = 116;
const MIN_ZOOM = 0.5;
const MAX_ZOOM = 2;

export function ChainGraph({chain, entities, selection, onSelect}: {chain: Chain; entities: Entity[]; selection: Selection; onSelect: (s: Selection) => void}) {
  const marker = useId().replace(/:/g, '');
  const idBase = useId().replace(/:/g, '');
  const narrow = useMediaQuery('(max-width: 720px)');
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({x: 0, y: 0});
  const scrollRef = useRef<HTMLDivElement>(null);
  const drag = useRef<{x: number; y: number; panX: number; panY: number; moved: boolean} | null>(null);
  const suppressClick = useRef(false);
  // Coordinates are display only. Existing source/target IDs define every arrow.
  const nodes = useMemo(() => [...chain.nodes].sort((a, b) => a.start_time.localeCompare(b.start_time) || a.node_id.localeCompare(b.node_id)), [chain.nodes]);
  const positions = useMemo(() => new Map(nodes.map((node, index) => [node.node_id, narrow ? {x: 24, y: 42 + index * 150} : {x: 24 + (index % 3) * 300, y: 42 + Math.floor(index / 3) * 178}])), [nodes, narrow]);
  const width = narrow ? 312 : Math.max(310, Math.min(nodes.length, 3) * 300 + 24);
  const height = narrow ? Math.max(210, nodes.length * 150 + 50) : Math.max(210, Math.ceil(nodes.length / 3) * 178 + 50);
  const showEdgeLabels = chain.edges.length <= 12 || Boolean(selection?.kind === 'edge');
  const label = (node: ChainNode) => node.entity_ids.map(i => entities.find(e => e.entity_id === i)?.display_value ?? entities.find(e => e.entity_id === i)?.value).filter(Boolean).slice(0, 2).join(' · ');

  function select(value: Selection) {if (suppressClick.current) {suppressClick.current = false;return;}onSelect(value);}
  function keyboard(event: React.KeyboardEvent, value: Selection, list: {kind: 'node' | 'edge'; id: string}[]) {
    const index = list.findIndex(item => item.kind === value?.kind && item.id === value?.id);
    const jump = (next: number) => {event.preventDefault();onSelect(list[Math.max(0, Math.min(list.length - 1, next))]);};
    if (event.key === 'Enter' || event.key === ' ') {event.preventDefault();select(value);}
    else if (event.key === 'ArrowRight' || event.key === 'ArrowDown') jump(index + 1);
    else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') jump(index - 1);
    else if (event.key === 'Home') jump(0);
    else if (event.key === 'End') jump(list.length - 1);
  }

  useEffect(() => {
    const element = scrollRef.current;
    if (!element) return;
    const onWheel = (event: WheelEvent) => {
      if (!(event.ctrlKey || event.metaKey)) return;
      event.preventDefault();
      setZoom(current => Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, current - Math.sign(event.deltaY) * 0.1)));
    };
    element.addEventListener('wheel', onWheel, {passive: false});
    return () => element.removeEventListener('wheel', onWheel);
  }, []);

  function resetView() {setZoom(1);setPan({x: 0, y: 0});}
  function fitView() {
    const element = scrollRef.current;
    if (!element) return;
    const next = Math.max(MIN_ZOOM, Math.min(1, Math.min((element.clientWidth - 16) / width, (element.clientHeight - 16) / height)));
    setZoom(Number(next.toFixed(2)));
    setPan({x: 0, y: 0});
  }

  return <div>
    <div className="graph-toolbar">
      <span className="muted">{nodes.length} 节点 · {chain.edges.length} 有向边 · 置信分为算法分{narrow ? ' · 上下滑动查看' : ''}</span>
      <button aria-label="适应攻击链视图" onClick={fitView} type="button"><TraceIcon icon={Maximize2} size={13}/></button><button aria-label="缩小攻击链" onClick={() => setZoom(z => Math.max(MIN_ZOOM, z - 0.25))} type="button"><TraceIcon icon={Minus} size={14}/></button>
      <button onClick={resetView} type="button"><TraceIcon icon={RotateCcw} size={13}/><span className="sr-only">重置攻击链缩放</span>{Math.round(zoom * 100)}%</button>
      <button aria-label="放大攻击链" onClick={() => setZoom(z => Math.min(MAX_ZOOM, z + 0.25))} type="button"><TraceIcon icon={Plus} size={14}/></button>
    </div>
    {!nodes.length ? <Notice>当前快照没有可展示节点。</Notice> : <div className="graph-scroll" ref={scrollRef}>
      <svg aria-label="生产攻击链图" className="chain-graph" height={height} role="group" style={{cursor: drag.current ? 'grabbing' : 'grab'}} viewBox={`0 0 ${width} ${height}`} width={width}
        onPointerDown={event => {if (event.button !== 0) return;drag.current = {x: event.clientX, y: event.clientY, panX: pan.x, panY: pan.y, moved: false};suppressClick.current = false;}}
        onPointerMove={event => {if (!drag.current) return;const dx = event.clientX - drag.current.x, dy = event.clientY - drag.current.y;if (Math.hypot(dx, dy) > 3) {drag.current.moved = true;suppressClick.current = true;}if (drag.current.moved) setPan({x: drag.current.panX + dx, y: drag.current.panY + dy});}}
        onPointerUp={() => {drag.current = null;}}
        onPointerCancel={() => {drag.current = null;}}
      >
        <g transform={`translate(${pan.x} ${pan.y}) scale(${zoom})`}>
          <defs><marker id={marker} markerHeight="9" markerWidth="9" orient="auto-start-reverse" refX="9" refY="5" viewBox="0 0 10 10"><path d="M 0 0 L 10 5 L 0 10 z" fill="#296b8f"/></marker></defs>
          {([...chain.edges].sort((a, b) => a.edge_id.localeCompare(b.edge_id))).map(edge => {
            const s = positions.get(edge.source_node_id), t = positions.get(edge.target_node_id);
            if (!s || !t) return null;
            const sameRow = t.y === s.y;
            const forward = t.x > s.x;
            const sx = s.x + (sameRow ? (forward ? NODE_WIDTH : 0) : NODE_WIDTH / 2), sy = s.y + (sameRow ? NODE_HEIGHT / 2 : (t.y > s.y ? NODE_HEIGHT : 0));
            const tx = t.x + (sameRow ? (forward ? 0 : NODE_WIDTH) : NODE_WIDTH / 2), ty = t.y + (sameRow ? NODE_HEIGHT / 2 : (t.y > s.y ? 0 : NODE_HEIGHT));
            const d = sameRow ? `M ${sx} ${sy} C ${(sx + tx) / 2} ${sy - 28}, ${(sx + tx) / 2} ${ty - 28}, ${tx} ${ty}` : `M ${sx} ${sy} C ${sx} ${(sy + ty) / 2}, ${tx} ${(sy + ty) / 2}, ${tx} ${ty}`;
            const selected = selection?.kind === 'edge' && selection.id === edge.edge_id;
            const value = {kind: 'edge' as const, id: edge.edge_id};
            return <g aria-label={`选择边 ${relationLabel(edge.relation_type)} ${shortId(edge.edge_id)}`} aria-pressed={selected} className={selected ? 'graph-edge selected' : 'graph-edge'} data-source={edge.source_node_id} data-target={edge.target_node_id} key={edge.edge_id}
              onClick={() => select(value)} onKeyDown={event => keyboard(event, value, chain.edges.map(item => ({kind: 'edge' as const, id: item.edge_id})))} role="button" tabIndex={0}>
              <path className="edge-hit" d={d} fill="none"/><path className="edge-line" d={d} fill="none" markerEnd={`url(#${marker})`}/>{showEdgeLabels && <text className="edge-label" textAnchor="middle" x={(sx + tx) / 2} y={(sy + ty) / 2 - 12}>{relationLabel(edge.relation_type)}</text>}
            </g>;
          })}
          {nodes.map(node => {
            const position = positions.get(node.node_id)!;
            const selected = selection?.kind === 'node' && selection.id === node.node_id;
            const value = {kind: 'node' as const, id: node.node_id};
            return <g aria-label={`选择节点 ${categoryLabel(node.category)}${(label(node) || '未抽取关键实体').slice(0, 32)}${node.start_time.slice(11, 23)} UTC${node.alert_ids.length} 告警 · 置信度 ${node.confidence.toFixed(2)} ${shortId(node.node_id)}`} aria-pressed={selected} className={selected ? 'graph-node selected' : 'graph-node'} key={node.node_id} onClick={() => select(value)} onKeyDown={event => keyboard(event, value, nodes.map(item => ({kind: 'node' as const, id: item.node_id})))} role="button" tabIndex={0} transform={`translate(${position.x},${position.y})`}>
              <rect height={NODE_HEIGHT} rx="10" width={NODE_WIDTH}/>
              <text aria-hidden="true" className="node-category" x="16" y="27">{categoryLabel(node.category)}</text>
              <text aria-hidden="true" x="16" y="49">{(label(node) || '未抽取关键实体').slice(0, 32)}</text>
              <text aria-hidden="true" x="16" y="72">{node.start_time.slice(11, 23)} UTC</text>
              <text aria-hidden="true" x="16" y="95">{node.alert_ids.length} 告警 · 置信度 {node.confidence.toFixed(2)}</text>
              <rect className="node-confidence-track" height="4" rx="2" width={NODE_WIDTH - 32} x="16" y="104"/>
              <rect className="node-confidence-value" height="4" rx="2" width={Math.max(4, (NODE_WIDTH - 32) * Math.max(0, Math.min(1, node.confidence)))} x="16" y="104"/>
            </g>;
          })}
        </g>
      </svg>
    </div>}
    <div aria-label="图例" className="graph-legend"><span><b>箭头</b> 传播方向</span><span><b>数字</b> 算法置信分</span><span><b>拖拽</b> 平移 · Ctrl/⌘+滚轮 缩放</span></div>
    {chain.edges.length === 0 && <Notice kind="info">未重构出已验证的传播边。{nodes.length === 1 ? '单节点仍可查看告警、证据和研判。' : '节点保持独立展示。'}</Notice>}
    {chain.status === 'partial' && <Notice kind="info">部分链：存在未确定方向或被拒绝的关联。</Notice>}
    {chain.unresolved_correlation_edge_ids.length > 0 && <details><summary>未定向关联（{chain.unresolved_correlation_edge_ids.length}）</summary>{chain.unresolved_correlation_edge_ids.map(id => <p key={id}><code>{id}</code></p>)}</details>}
    {chain.edges.length > 0 && <div aria-label="攻击链边列表" className="edge-navigation">{chain.edges.map(e => <button key={e.edge_id} onClick={() => onSelect({kind: 'edge', id: e.edge_id})} type="button">{shortId(e.source_node_id)} → {shortId(e.target_node_id)} · {relationLabel(e.relation_type)}</button>)}</div>}
  </div>;
}
