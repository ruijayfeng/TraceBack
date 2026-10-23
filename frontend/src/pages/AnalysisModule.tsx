import {useState} from 'react';
import type {ReactNode} from 'react';
import type {Stage, StageAnalysis} from '../types/stageAnalysis';
import {Notice, Pager, StableId, Time} from '../components/common';
import {Icon} from '../components/Icon';
import {behaviorName, sourceLabel} from '../lib/displayLabels';
import {EvidenceDrawer, relationLabels} from './StageWorkbench';

const labels: Record<string,string>={alerts:'安全告警',scenes:'攻击场景',evidence:'证据追溯',records:'分析记录'};
const hints: Record<string,string>={alerts:'检索当前快照中的告警索引，展开设备原始记录。',scenes:'按调查分组浏览行为阶段，进入对应攻击链。',evidence:'核对阶段成员、已接受关系与拒绝建边的原始依据。',records:'当前分析的来源、版本和结果口径。'};
type Row={id:string;cells:ReactNode[];search:string;source:string[];behavior:string[];open:()=>void;action:string};
export default function AnalysisModule({view,data,onOpenChain}: {view:string;data:StageAnalysis;onOpenChain:(id:string)=>void}) {
  const params=new URLSearchParams(location.search);
  const [query,setQuery]=useState(params.get('q')??''),[source,setSource]=useState(params.get('source')??''),[behavior,setBehavior]=useState(params.get('behavior')??'');
  const [page,setPage]=useState(Math.max(1,Number(params.get('page'))||1));
  const [selection,setSelection]=useState<{id:string;title:string;raw?:boolean}|null>(null);
  const [evidenceKind,setEvidenceKind]=useState(params.get('kind')??'stages');
  function update(q:string,s:string,b:string,p:number,k=evidenceKind) {
    setQuery(q);setSource(s);setBehavior(b);setPage(p);setEvidenceKind(k);
    const url=new URL(location.href);
    for(const [key,value] of Object.entries({q,source:s,behavior:b,page:p>1?String(p):'',kind:view==='evidence'?k:''})) {if(value)url.searchParams.set(key,value);else url.searchParams.delete(key);}
    history.replaceState({},'',url);
  }
  const stageIndex=new Map(data.stages.map(s=>[s.stage_id,s]));
  const sourceOptions=[...new Set(data.stages.flatMap(s=>s.source_types))].sort();
  const behaviorOptions=[...new Set(data.stages.map(s=>s.behavior))].sort();
  const openStage=(s:Stage)=>setSelection({id:s.stage_id,title:'阶段证据：'+behaviorName(s.behavior)});
  let rows:Row[]=[], columns:string[]=[];
  if(view==='alerts') {
    columns=['告警 ID','所属阶段','阶段行为','所属阶段来源','操作'];
    const members=new Map<string,Stage[]>();
    data.stages.forEach(s=>s.alert_ids.forEach(id=>members.set(id,[...(members.get(id)??[]),s])));
    rows=[...members].map(([id,stages])=>({id,cells:[<StableId value={id}/>,<span title={stages.map(s=>s.stage_id).join('\n')}>{stages.map(s=>s.stage_id.slice(0,16)).join(' / ')}</span>,[...new Set(stages.map(s=>behaviorName(s.behavior)))].join(' / '),[...new Set(stages.flatMap(s=>s.source_types))].map(sourceLabel).join(' / ')],search:[id,...stages.flatMap(s=>[s.stage_id,s.behavior,behaviorName(s.behavior)])].join(' '),source:stages.flatMap(s=>s.source_types),behavior:stages.map(s=>s.behavior),open:()=>setSelection({id,title:'原始告警',raw:true}),action:'查看原始告警'}));
  } else if(view==='scenes') {
    columns=['调查分组','行为阶段','成员告警','数据来源','关联链结构','操作'];
    const communities=new Map<string,Stage[]>();
    data.stages.forEach(s=>communities.set(s.community_id,[...(communities.get(s.community_id)??[]),s]));
    rows=[...communities].map(([id,stages],i)=>{
      const chains=data.chains.filter(c=>c.stage_ids.some(s=>stages.some(stage=>stage.stage_id===s)));
      return {id,cells:[<><b>场景 {i+1}</b><small className="row-subtitle"><StableId value={id}/></small></>,stages.length,new Set(stages.flatMap(s=>s.alert_ids)).size,[...new Set(stages.flatMap(s=>s.source_types))].map(sourceLabel).join(' / '),chains.length],search:[id,...stages.map(s=>behaviorName(s.behavior))].join(' '),source:stages.flatMap(s=>s.source_types),behavior:stages.map(s=>s.behavior),open:()=>onOpenChain(chains[0]?.chain_id??''),action:'查看攻击链'};
    });
  } else if(view==='evidence') {
    if(evidenceKind==='stages') {
      columns=['阶段','行为','观测起始时间','成员告警','来源','操作'];
      rows=data.stages.map(s=>({id:s.stage_id,cells:[<StableId value={s.stage_id}/>,behaviorName(s.behavior),<Time value={s.start_time}/>,s.alert_count,s.source_types.map(sourceLabel).join(' / ')],search:[s.stage_id,s.behavior,behaviorName(s.behavior)].join(' '),source:s.source_types,behavior:[s.behavior],open:()=>openStage(s),action:'查看阶段证据'}));
    } else {
      columns=['关系类型','阶段连接','关系 ID','操作'];
      const decisions=evidenceKind==='rejected'?(data.decisions??[]).filter(r=>r.relation_type==='NO_RELATION'):data.relations;
      rows=decisions.map(r=>{
        const stages=[stageIndex.get(r.from_stage_id??r.stage_a_id),stageIndex.get(r.to_stage_id??r.stage_b_id)].filter((s):s is Stage=>!!s);
        return {id:r.relation_id,cells:[<span className={'badge '+(r.relation_type==='NO_RELATION'?'warning':'verified')}>{relationLabels[r.relation_type]}</span>,stages.map(s=>behaviorName(s.behavior)).join(r.from_stage_id?' → ':' — '),<StableId value={r.relation_id}/>],search:[r.relation_id,r.reason,...stages.flatMap(s=>[s.stage_id,behaviorName(s.behavior)])].join(' '),source:stages.flatMap(s=>s.source_types),behavior:stages.map(s=>s.behavior),open:()=>setSelection({id:r.relation_id,title:'关系证据：'+relationLabels[r.relation_type]}),action:'查看关系证据'};
      });
    }
  }
  const filtered=rows.filter(r=>(!query || r.search.toLowerCase().includes(query.toLowerCase())) && (!source || r.source.includes(source)) && (!behavior || r.behavior.includes(behavior)));
  const current=Math.min(page,Math.max(1,Math.ceil(filtered.length/10)));
  return <div className="module-page"><div className="overview-heading"><div><h1>{labels[view]}</h1><p>{hints[view]}</p></div><span className="badge verified">{data.status==='sealed'?'已封存':'只读'} · {data.counts.input_count} 条输入告警</span></div>
    {view==='records'?<section className="panel record-panel"><div className="section-heading"><h2>当前分析快照</h2><Icon name="file"/></div><dl className="record-facts"><dt>分析 ID</dt><dd><code>{data.analysis_id}</code></dd><dt>算法版本</dt><dd>{data.algorithm_version}</dd><dt>快照状态</dt><dd>{data.status}</dd>{data.data_source && <><dt>数据产物目录</dt><dd><code>{data.data_source}</code></dd></>}<dt>事实来源</dt><dd>{data.source_stage===9?'正式第 9 阶段攻击链重建产物':'历史阶段分析产物'}</dd><dt>结果规模</dt><dd>{data.counts.input_count} 条告警 / {data.counts.stage_count} 个阶段 / {data.counts.relation_count} 条关系 / {data.counts.chain_count} 条链结构</dd></dl><Notice kind="info">链结构用于调查，不直接代表已确认独立攻击。当前快照未提供风险评分和人工处置状态。</Notice></section>:<>
      {view==='evidence' && <nav className="view-tabs" aria-label="证据分类">{[['stages','阶段证据',data.stages.length],['relations','关系证据',data.relations.length],['rejected','拒绝建边',(data.decisions??[]).filter(r=>r.relation_type==='NO_RELATION').length]].map(([id,label,count])=><button key={id} aria-pressed={evidenceKind===id} onClick={()=>update(query,source,behavior,1,String(id))}>{label}<span>{count}</span></button>)}</nav>}
      <section className="panel module-table-panel"><div className="module-filters"><label className="scope-search"><Icon name="search"/><input aria-label="搜索当前列表" placeholder={view==='alerts'?'搜索告警 ID、阶段或行为…':'搜索 ID 或阶段行为…'} value={query} onChange={e=>update(e.target.value,source,behavior,1)}/></label><label>阶段来源<select value={source} onChange={e=>update(query,e.target.value,behavior,1)}><option value="">全部来源</option>{sourceOptions.map(s=><option key={s} value={s}>{sourceLabel(s)}</option>)}</select></label><label>阶段行为<select value={behavior} onChange={e=>update(query,source,e.target.value,1)}><option value="">全部行为</option>{behaviorOptions.map(b=><option key={b} value={b}>{behaviorName(b)}</option>)}</select></label><button onClick={()=>update('','','',1)}>重置筛选</button></div>
        <div className="section-heading"><h2>{view==='alerts'?'告警索引':view==='scenes'?'调查分组':evidenceKind==='stages'?'阶段证据':evidenceKind==='relations'?'关系证据':'拒绝建边决策'}</h2><span className="muted">{filtered.length} 条结果 · 每页 10 条</span></div>
        <div className="table-scroll"><table><thead><tr>{columns.map(c=><th key={c}>{c}</th>)}</tr></thead><tbody>{filtered.slice((current-1)*10,current*10).map(r=><tr key={r.id}>{r.cells.map((cell,i)=><td key={i}>{cell}</td>)}<td><button className="text-button" onClick={r.open}>{r.action}</button></td></tr>)}</tbody></table></div>
        {!filtered.length && <Notice>没有匹配的记录，请调整搜索或筛选条件。</Notice>}<Pager page={current} total={filtered.length} size={10} onChange={p=>update(query,source,behavior,p)}/>
      </section>{view==='alerts' && <p className="muted">列表中的行为与来源描述所属阶段；单条告警的准确字段请展开原始记录核对。</p>}
    </>}
    {selection && <EvidenceDrawer key={data.analysis_id+selection.id} analysisId={data.analysis_id} subjectId={selection.id} title={selection.title} rawAlert={selection.raw} onClose={()=>setSelection(null)}/>}
  </div>;
}
