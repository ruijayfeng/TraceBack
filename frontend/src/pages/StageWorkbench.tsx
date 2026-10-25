import {useEffect, useRef, useState} from 'react';
import {api} from '../api/client';
import {useResource} from '../api/hooks';
import {JsonView, Notice, Pager, Section, StableId, Time} from '../components/common';
import {categoryLabel, sourceLabel} from '../lib/displayLabels';
import {FLOW_NODE_HEIGHT, FLOW_NODE_WIDTH, flowRelations, layoutStageFlow} from '../lib/stageFlow';
import type {Stage, StageAnalysis, StageCatalog, StageRelation, StageChain, RelationKind} from '../types/stageAnalysis';
import '../styles/stageAnalysis.css';
import {StageAIReport} from '../components/StageAIReport';

const behaviorNames: Record<string,string> = {WEB_EXPLOIT:'Web 利用',EXECUTION:'执行活动',CREDENTIAL_ACTIVITY:'凭据活动',FILE_ACTIVITY:'文件活动',NETWORK_ACTIVITY:'网络活动'};
const behavior = (value: string) => behaviorNames[value] ?? categoryLabel(value.toLowerCase());
export const relationLabels: Record<RelationKind | 'DIRECTED_EDGE' | 'UNDIRECTED_EDGE' | 'NO_RELATION', string> = {STRONG_DIRECTED:'强有向关系', STRONG_UNDIRECTED:'强无向关系', WEAK_DIRECTED:'弱时间关系', DIRECTED_EDGE:'有向关系', UNDIRECTED_EDGE:'无向关系', NO_RELATION:'拒绝建边'};
// The renderer-facing strength; relation_type stays the authoritative value.
const displayKind = (r: {relation_type: string; display_kind?: string}) => r.display_kind ?? r.relation_type;

export function StageGraph({stages, relations, selected, onSelect}: {stages: Stage[]; relations: StageRelation[]; selected: string; onSelect: (id: string) => void}) {
  const [expanded,setExpanded]=useState(false), [zoom,setZoom]=useState<number | null>(null), [canvasWidth,setCanvasWidth]=useState(960), [canvasHeight,setCanvasHeight]=useState(500);
  const canvas=useRef<HTMLDivElement>(null);
  const layout=layoutStageFlow(stages,relations), simplified=flowRelations(relations,stages);
  const visible=expanded?relations:simplified;
  useEffect(()=>{
    const element=canvas.current;if(!element) return;
    const resize=()=>{if(element.clientWidth) setCanvasWidth(element.clientWidth);if(element.clientHeight)setCanvasHeight(element.clientHeight);};
    resize();if(typeof ResizeObserver==='undefined') return;
    const observer=new ResizeObserver(resize);observer.observe(element);return()=>observer.disconnect();
  },[]);
  if(!stages.length) return <Notice>该事件没有可展示的阶段。</Notice>;
  const nodes=new Map(layout.nodes.map(node=>[node.stage.stage_id,node]));
  const minX=Math.min(...layout.nodes.map(node=>node.x));
  const routed=visible.map(r=>({relation:r,from:nodes.get(r.from_stage_id ?? r.stage_a_id)!,to:nodes.get(r.to_stage_id ?? r.stage_b_id)!}));
  const lanes: {start:number;end:number}[][]=[];
  const paths=routed.map(({relation:r,from,to})=>{
    const outgoing=routed.filter(edge=>edge.from===from), incoming=routed.filter(edge=>edge.to===to);
    const x1=from.x+35+(outgoing.findIndex(edge=>edge.relation===r)+1)*150/(outgoing.length+1);
    const x2=to.x+35+(incoming.findIndex(edge=>edge.relation===r)+1)*150/(incoming.length+1);
    const y1=from.y+FLOW_NODE_HEIGHT, y2=to.y;
    if(to.y===from.y && Math.abs(to.x-from.x)===280) {
      const forward=to.x>from.x, start=from.x+(forward?FLOW_NODE_WIDTH:0), end=to.x+(forward?0:FLOW_NODE_WIDTH), y=from.y+FLOW_NODE_HEIGHT/2;
      return {relation:r,path:`M${start},${y} H${end}`,x:(start+end)/2,y:y-6};
    }
    if(to.y===from.y+148) return {relation:r,path:`M${x1},${y1} C${x1},${y1+34} ${x2},${y2-34} ${x2},${y2}`,x:(x1+x2)/2,y:(y1+y2)/2};
    const interval={start:Math.min(from.rank,to.rank),end:Math.max(from.rank,to.rank)};
    let lane=lanes.findIndex(items=>items.every(item=>item.end<interval.start || item.start>interval.end));
    if(lane<0) {lane=lanes.length;lanes.push([]);}lanes[lane].push(interval);
    return {relation:r,path:`M${x1},${y1} V${y1+20} H${minX-24-lane*9} V${y2-22} H${x2} V${y2}`,x:x2,y:y2-28};
  });
  // Reserve a gutter for long-range and cycle edges, clear of stage cards.
  const gutter=Math.max(0,lanes.length*9+40-minX), width=layout.width+gutter;
  const actualScale=zoom ?? Math.max(.1,Math.min(1,(canvasWidth-32)/width,(canvasHeight-32)/layout.height));
  const strongCount=relations.filter(r=>displayKind(r)==='STRONG_DIRECTED').length;
  return <div className="event-flow">
    <div className="event-flow-heading"><div><h3>事件攻击流程</h3><p className="muted">从上往下沿箭头查看各阶段的分支与汇合；点击阶段或连线查看证据。</p></div><span className="badge">全部 {stages.length} 个阶段</span></div>
    {!strongCount && relations.length>0 && <Notice>该事件目前只有{relations.some(r=>displayKind(r)==='STRONG_UNDIRECTED')?'未定向强关系和':''}弱时间关系，尚不能确认因果攻击流程。</Notice>}
    {stages.length===1 && <Notice>该事件只有一个阶段，目前没有跨阶段连线。</Notice>}
    {layout.hasCycle && <Notice>存在循环关系，已保留回环连线；图中不强行指定起点与终点。</Notice>}
    <div className="event-flow-toolbar"><div className="event-flow-legend"><span><i className="flow-solid"/>强有向关系</span><span><i className="flow-unresolved"/>强无向关系</span><span><i className="flow-weak"/>弱时间关系</span></div><label><input type="checkbox" checked={expanded} onChange={e=>setExpanded(e.target.checked)}/> 展开全部关系</label></div>
    <div className="event-flow-controls"><span>{visible.length} 条连线{!expanded && relations.length>visible.length?` · 已折叠 ${relations.length-visible.length} 条同类跨线`:''}</span><button onClick={()=>setZoom(Math.max(.15,actualScale/1.25))} aria-label="缩小流程图">−</button><span>{Math.round(actualScale*100)}%</span><button onClick={()=>setZoom(Math.min(2,actualScale*1.25))} aria-label="放大流程图">＋</button><button onClick={()=>setZoom(null)}>查看全图</button><button onClick={()=>setZoom(Math.min(1,(canvasWidth-32)/width))}>适合宽度</button></div>
    <div ref={canvas} className="event-flow-canvas" tabIndex={0} aria-label="事件流程画布，可滚动查看放大后的流程"><svg className="chain-graph" width={width*actualScale} height={layout.height*actualScale} viewBox={`0 0 ${width} ${layout.height}`} aria-label="事件完整攻击流程图">
      <defs><marker id="stage-arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10Z" fill="#28798e"/></marker><marker id="stage-weak-arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10Z" fill="#ae843b"/></marker></defs>
      <g transform={`translate(${gutter},0)`}>
        <text className="flow-direction" x={layout.width/2} y="35" textAnchor="middle">事件阶段与关系 · 沿箭头向下阅读</text>
        {paths.map(({relation:r,path,x,y})=>{const k=displayKind(r);return <g key={r.relation_id} role="button" tabIndex={0} aria-label={`查看${relationLabels[r.relation_type]}证据 ${r.relation_id}`} onClick={()=>onSelect(r.relation_id)} onKeyDown={e=>{if(e.key==='Enter' || e.key===' '){e.preventDefault();onSelect(r.relation_id);}}} className={'graph-edge '+(selected===r.relation_id?'selected':'')} data-source={r.from_stage_id ?? ''} data-target={r.to_stage_id ?? ''} data-relation-id={r.relation_id}>
          <title>{relationLabels[r.relation_type]} · {r.reason}</title><path className="edge-hit" d={path} fill="none"/><path className="edge-line" d={path} fill="none" style={{stroke:k==='WEAK_DIRECTED'?'#ae843b':k==='STRONG_UNDIRECTED'?'#7d6a9f':'#28798e',strokeDasharray:k==='WEAK_DIRECTED'?'6 5':undefined}} markerEnd={k==='STRONG_UNDIRECTED'?undefined:`url(#${k==='WEAK_DIRECTED'?'stage-weak-arrow':'stage-arrow'})`}/><text className="edge-label" x={x+8} y={y-5}>{relationLabels[r.relation_type]}</text>
        </g>;})}
        {layout.nodes.map(({stage:s,x,y,index})=><g key={s.stage_id} role="button" tabIndex={0} aria-label={`查看阶段 ${index} ${behavior(s.behavior)}`} className={'graph-node '+(selected===s.stage_id?'selected':'')} data-stage-id={s.stage_id} transform={`translate(${x},${y})`} onClick={()=>onSelect(s.stage_id)} onKeyDown={e=>{if(e.key==='Enter' || e.key===' '){e.preventDefault();onSelect(s.stage_id);}}}><title>{index}. {behavior(s.behavior)} · {s.start_time} · {s.alert_count} 条告警</title><rect width={FLOW_NODE_WIDTH} height={FLOW_NODE_HEIGHT} rx="9"/><text x="15" y="26" className="node-category">{index}. {behavior(s.behavior)}</text><text x="15" y="48">{s.alert_count} 条告警 · {s.source_types.map(sourceLabel).join(' / ')}</text><text x="15" y="67" className="flow-node-time">{s.start_time.slice(11,19)} UTC</text></g>)}
      </g>
    </svg></div>
    <p className="muted">阶段编号按观测时间排列，箭头保留原始证据方向。虚线只表示时间关联；紫色无箭头线表示方向未定。{relations.length>simplified.length?'概览仅折叠同种证据、同种关系中可沿其他连线到达的跨线；展开后查看全部原始关系。':''}</p>
  </div>;
}

function RawAlert({analysisId, alertId}: {analysisId: string; alertId: string}) {
  const raw = useResource(signal => api.stageRaw(analysisId,alertId,signal),[analysisId,alertId]);
  return <>{raw.loading && <Notice kind="loading">正在读取原始告警…</Notice>}{raw.error && <Notice kind="error">{raw.error}</Notice>}{raw.data && <JsonView value={raw.data.raw_alert} title="原始告警"/>}</>;
}

function TracePanel({analysisId, subjectId}: {analysisId: string; subjectId: string}) {
  const resource = useResource(signal => api.stageTrace(analysisId,subjectId,signal),[analysisId,subjectId]);
  const [raw,setRaw] = useState('');
  const data=resource.data;
  return <Section title="证据追溯" hint="阶段 / 关系 → 见证告警 → 原始字段">
    {resource.loading && <Notice kind="loading">正在解析证据…</Notice>}{resource.error && <Notice kind="error">{resource.error}</Notice>}
    {data && <><p>{data.trace.evidence_summary}</p><p className="muted">对象：<StableId value={subjectId}/></p>
      {data.trace.stage && <dl className="record-facts">
        <dt>Stage ID</dt><dd><code>{data.trace.stage.stage_id}</code></dd>
        <dt>行为</dt><dd>{data.trace.stage.behavior}</dd>
        <dt>告警数量</dt><dd>{data.trace.stage.alert_count}</dd>
        <dt>开始时间</dt><dd><Time value={data.trace.stage.start_time}/></dd>
        <dt>结束时间</dt><dd><Time value={data.trace.stage.end_time}/></dd>
        <dt>Host</dt><dd>{data.trace.stage.host_entities.map(e=>e.display_value).join(' / ') || '未观测'}</dd>
        <dt>Account</dt><dd>{data.trace.stage.account_entities.map(e=>e.display_value).join(' / ') || '未观测'}</dd>
        <dt>Process</dt><dd>{data.trace.stage.process_entities.map(e=>e.display_value).join(' / ') || '未观测'}</dd>
        <dt>数据源（原生记录）</dt><dd>{data.trace.stage.observed_sources.join(' / ')}</dd>
      </dl>}
      {data.trace.relation_type && <dl className="record-facts"><dt>Relation Type</dt><dd>{data.trace.relation_type}</dd><dt>Evidence Type</dt><dd>{data.trace.evidence_types?.join(' / ')}</dd><dt>Evidence Reason</dt><dd>{data.trace.reason}</dd></dl>}
      <div className="table-scroll"><table><thead><tr><th>见证告警</th><th>来源</th><th>观测时间</th><th>证据</th></tr></thead><tbody>{data.trace.witness_alerts.map(a => <tr key={a.alert_id}><td><StableId value={a.alert_id}/>{(data.trace.winning_witness_alert_ids ?? []).includes(a.alert_id) && <span className="badge verified">主证据</span>}</td><td>{a.source_type ? sourceLabel(a.source_type) : '—'}</td><td>{a.timestamp ? <Time value={a.timestamp}/> : '—'}</td><td><button onClick={() => setRaw(raw===a.alert_id?'':a.alert_id)}>{raw===a.alert_id?'收起原始告警':'查看原始告警'}</button></td></tr>)}</tbody></table></div>
      {raw && <RawAlert key={raw} analysisId={analysisId} alertId={raw}/>}
      <details className="diagnostics"><summary>已解析的字段指针（{data.resolved_pointers.length}）</summary><JsonView value={data.resolved_pointers} title="全部字段指针"/></details>
    </>}
  </Section>;
}

export function EvidenceDrawer({analysisId,subjectId,title,reason,onClose,rawAlert=false}: {analysisId: string;subjectId: string;title: string;reason?: string;onClose:()=>void;rawAlert?:boolean}) {
  const dialog=useRef<HTMLDialogElement>(null);
  useEffect(()=>{
    const element=dialog.current!;
    const previous=document.activeElement as HTMLElement | null;
    const overflow=document.body.style.overflow, padding=document.body.style.paddingRight;
    const gap=window.innerWidth-document.documentElement.clientWidth;
    document.body.style.overflow='hidden';
    if(gap>0) document.body.style.paddingRight=`${gap}px`;
    if(element.showModal) element.showModal(); else element.setAttribute('open','');
    return ()=>{
      element.close?.();document.body.style.overflow=overflow;document.body.style.paddingRight=padding;
      previous?.focus({preventScroll:true});
    };
  },[]);
  return <dialog ref={dialog} className="stage-evidence-drawer" aria-labelledby="stage-evidence-title" onCancel={e=>{e.preventDefault();onClose();}} onClick={e=>{
    if(e.target!==e.currentTarget) return;
    const rect=e.currentTarget.getBoundingClientRect();
    if(e.clientX<rect.left || e.clientX>rect.right || e.clientY<rect.top || e.clientY>rect.bottom) onClose();
  }}><div className="drawer-heading"><div><span className="eyebrow">事件调查 / 证据</span><h2 id="stage-evidence-title">{title}</h2></div><button onClick={onClose} aria-label="关闭证据" autoFocus>×</button></div><div className="stage-evidence-content">{reason && <p>{reason}</p>}{rawAlert?<RawAlert key={analysisId+subjectId} analysisId={analysisId} alertId={subjectId}/>:<TracePanel key={analysisId+subjectId} analysisId={analysisId} subjectId={subjectId}/>}</div></dialog>;
}

export function StageAnalysisView({data}: {data: StageAnalysis}) {
  const is9 = data.source_stage === 9 || data.algorithm_version === 'attack-chain-reconstruction-v1';
  const dirOf=(c:StageChain)=>is9?(c.directed_count??0):(c.strong_directed_count??0);
  const undOf=(c:StageChain)=>is9?(c.undirected_count??0):(c.strong_undirected_count??0);
  const chains=[...data.chains].sort((a,b)=>dirOf(b)-dirOf(a) || b.stage_count-a.stage_count || a.chain_id.localeCompare(b.chain_id));
  const params=new URLSearchParams(location.search);
  const requested=params.get('chain_id');
  const [chainId,setChainId]=useState(chains.find(c=>c.chain_id===requested)?.chain_id ?? chains[0]?.chain_id ?? '');
  const [selected,setSelected]=useState(''),[kind,setKind]=useState('all'),[page,setPage]=useState(1);
  const [panel,setPanel]=useState(['graph','timeline','relations','audit'].includes(params.get('panel')??'')?params.get('panel')!:'graph');
  function changeView(id:string,nextPanel=panel) {
    setChainId(id);setPanel(nextPanel);setPage(1);setSelected('');setKind('all');
    const url=new URL(location.href);url.searchParams.set('chain_id',id);url.searchParams.set('panel',nextPanel);
    history.replaceState({},'',url);
  }
  const chain=chains.find(c=>c.chain_id===chainId);
  const stages=data.stages.filter(s=>chain?.stage_ids.includes(s.stage_id)).sort((a,b)=>a.start_time.localeCompare(b.start_time) || a.stage_id.localeCompare(b.stage_id));
  const relations=data.relations.filter(r=>chain?.relation_ids.includes(r.relation_id));
  const filtered=relations.filter(r=>kind==='all' || r.relation_type===kind);
  const rejected=(data.decisions??[]).filter(r=>r.relation_type==='NO_RELATION');
  const stageName=(id:string)=>{const i=stages.findIndex(s=>s.stage_id===id);const s=data.stages.find(s=>s.stage_id===id);return i>=0?`${i+1}. ${behavior(stages[i].behavior)}`:s?`${behavior(s.behavior)} (${s.stage_id.slice(-6)})`:id;};
  const selectedStage=data.stages.find(s=>s.stage_id===selected),selectedRelation=[...data.relations,...rejected].find(r=>r.relation_id===selected);
  const counts=data.counts;
  const metrics:[number,string][]=is9?[[counts.input_count,'输入告警'],[counts.stage_count,'行为阶段'],[counts.relation_count,'已接受关系'],[counts.chain_count,'攻击链结构'],[data.chains.filter(c=>!c.single_stage).length,'主体攻击链'],[data.chains.filter(c=>c.single_stage).length,'孤立阶段'],[counts.directed_count??0,'有向关系'],[counts.undirected_count??0,'无向关系'],[counts.no_relation_count??0,'拒绝建边']]:[[counts.input_count,'输入告警'],[counts.stage_count,'行为阶段'],[counts.relation_count,'阶段关系'],[counts.chain_count,'事件'],[counts.strong_directed_count??0,'强有向关系'],[counts.strong_undirected_count??0,'强无向关系'],[counts.weak_directed_count??0,'弱时间关系']];
  const directionBasis=(r:StageRelation)=>r.direction_basis==='temporal_order'?'观测时间先后':r.direction_basis==='unresolved' || r.direction_claim==='UNDIRECTED'?'方向未解决':'原始证据语义';
  return <div className="chain-page"><div className="overview-heading"><div><h1>{counts.input_count} 条告警分析</h1><p>选择攻击链，在流程、阶段与关系之间切换调查。</p></div><span className="badge verified">{is9?'正式⑨产物 · 证据可追溯':'证据可追溯'}</span></div>
    <div className="chain-metrics">{metrics.map(([value,title])=><article className="metric" key={title}><span>{title}</span><strong>{value}</strong></article>)}</div>
    <div className="chain-workspace"><aside className="chain-index"><div className="chain-index-title"><h2>链结构</h2><span>{chains.length}</span></div><div className="stage-chain-tabs">{chains.map((c,i)=><button key={c.chain_id} aria-pressed={c.chain_id===chainId} onClick={()=>changeView(c.chain_id)}><b>{is9?'攻击链':'事件'} {i+1}<span className="chain-shape">{c.single_stage?'单阶段':'多阶段'}</span></b><span>{c.stage_count} 阶段 · {c.relation_count} 关系</span><small>{dirOf(c)+undOf(c)} 强关联 / {c.weak_directed_count??0} 弱时间</small><small>{dirOf(c)} 有向 · {undOf(c)} 无向</small></button>)}</div></aside>
      <section className="chain-detail panel">{!chain?<Notice>该分析没有事件。</Notice>:<>
        <div className="chain-detail-heading"><div><h2>{is9?'攻击链':'事件'} {chains.indexOf(chain)+1}</h2><StableId value={chain.chain_id}/></div><span className="badge">{stages.length} 个阶段 · {relations.length} 条关系</span></div>
        <nav className="view-tabs" aria-label="攻击链视图">{[['graph','攻击流程'],['timeline','阶段列表'],['relations','关系列表'],...(is9?[['audit','拒绝建边']]:[])].map(([id,label])=><button key={id} aria-pressed={panel===id} onClick={()=>changeView(chainId,id)}>{label}</button>)}</nav>
        {panel==='graph' && <>{chain.single_stage && <Notice>该事件的 {stages[0]?.alert_count??0} 条告警已聚合为一个阶段。强关联数统计阶段之间的关系，单阶段不产生跨阶段连线。</Notice>}<StageGraph key={chainId} stages={stages} relations={relations} selected={selected} onSelect={setSelected}/></>}
        {panel==='timeline' && <div className="chain-table-view"><div className="section-heading"><h3>阶段时间线</h3><span className="muted">{stages.length} 个阶段</span></div><div className="table-scroll"><table><thead><tr><th>阶段</th><th>开始时间</th><th>告警</th><th>来源</th><th>证据</th></tr></thead><tbody>{stages.slice((page-1)*10,page*10).map((s,i)=><tr key={s.stage_id}><td>{(page-1)*10+i+1}. {behavior(s.behavior)}</td><td><Time value={s.start_time}/></td><td>{s.alert_count}</td><td>{s.source_types.map(sourceLabel).join(' / ')}</td><td><button className="text-button" onClick={()=>setSelected(s.stage_id)}>查看阶段证据</button></td></tr>)}</tbody></table></div><Pager page={page} size={10} total={stages.length} onChange={setPage}/></div>}
        {panel==='relations' && <div className="chain-table-view"><div className="section-heading"><h3>阶段关系</h3><label>关系类型<select value={kind} onChange={e=>{setKind(e.target.value);setPage(1);}}><option value="all">全部关系</option>{[...new Set(relations.map(r=>r.relation_type))].map(k=><option key={k} value={k}>{relationLabels[k]}</option>)}</select></label></div><div className="table-scroll"><table><thead><tr><th>关系</th><th>阶段连接</th><th>方向依据</th><th>证据</th></tr></thead><tbody>{filtered.slice((page-1)*10,page*10).map(r=><tr key={r.relation_id}><td><span className={'badge '+(displayKind(r)==='WEAK_DIRECTED'?'warning':'verified')}>{relationLabels[r.relation_type]}</span></td><td>{stageName(r.from_stage_id??r.stage_a_id)} {displayKind(r)==='STRONG_UNDIRECTED'?'—':'→'} {stageName(r.to_stage_id??r.stage_b_id)}</td><td>{directionBasis(r)}</td><td><button className="text-button" onClick={()=>setSelected(r.relation_id)}>查看关系证据</button></td></tr>)}</tbody></table></div>{!filtered.length && <Notice>该事件没有此类型的关系。</Notice>}<Pager page={page} size={10} total={filtered.length} onChange={setPage}/></div>}
        {panel==='audit' && <div className="chain-table-view"><div className="section-heading"><h3>拒绝建边决策</h3><span className="muted">全分析 · {rejected.length} 条 · 不进入攻击图</span></div><div className="table-scroll"><table><thead><tr><th>阶段对</th><th>关系 ID</th><th>证据</th></tr></thead><tbody>{rejected.slice((page-1)*10,page*10).map(r=><tr key={r.relation_id}><td>{stageName(r.stage_a_id)} — {stageName(r.stage_b_id)}</td><td><StableId value={r.relation_id}/></td><td><button className="text-button" onClick={()=>setSelected(r.relation_id)}>查看决策证据</button></td></tr>)}</tbody></table></div>{!rejected.length && <Notice>没有拒绝建边决策。</Notice>}<Pager page={page} size={10} total={rejected.length} onChange={setPage}/></div>}
        {is9 && <StageAIReport key={chainId} analysisId={data.analysis_id} chainId={chainId} onEvidence={setSelected}/>}
      </>}</section></div><p className="chain-disclaimer">箭头表达已有关系方向；弱关系只表示观测先后，无向关系保留未解决方向。图的连通性不代表已确认同一次攻击。</p>
    {selected && <EvidenceDrawer key={selected} analysisId={data.analysis_id} subjectId={selected} rawAlert={selected.startsWith('alt_')} title={selectedStage?`阶段证据：${behavior(selectedStage.behavior)}`:selectedRelation?`关系证据：${relationLabels[selectedRelation.relation_type]}`:'原始告警证据'} onClose={()=>setSelected('')}/>}
  </div>;
}

export default function StageWorkbench({analysisId, catalog, catalogError}: {analysisId: string; catalog: StageCatalog | null; catalogError: string | null}) {
  const identity=analysisId || catalog?.default_analysis_id || '';
  return catalogError && !identity ? <Notice kind="error">无法读取分析记录：{catalogError}</Notice> : !catalog && !identity ? <Notice kind="loading">正在查找新的分析结果…</Notice> : !identity ? <Notice>尚无可打开的阶段分析结果。</Notice> : <LoadStageAnalysis key={identity} analysisId={identity}/>;
}
function LoadStageAnalysis({analysisId}: {analysisId: string}) {
  const resource=useResource(signal=>api.stageAnalysis(analysisId,signal),[analysisId]);
  return <>{resource.loading && <Notice kind="loading">正在核验并读取告警、阶段与事件…</Notice>}{resource.error && <Notice kind="error">分析无法打开：{resource.error}</Notice>}{resource.data && <StageAnalysisView key={analysisId} data={resource.data}/>}</>;
}
