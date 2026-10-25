import {useEffect, useState} from 'react';
import {api} from '../api/client';
import {Notice, StableId} from './common';
import type {StageAIResult, StageAIFact} from '../types/stageAnalysis';

export function StageAIReport({analysisId, chainId, onEvidence}: {analysisId:string; chainId:string; onEvidence:(id:string)=>void}) {
  const [result,setResult]=useState<StageAIResult|null>(null),[busy,setBusy]=useState(false),[failed,setFailed]=useState(false);
  useEffect(()=>{
    const control=new AbortController();
    api.stageAISaved(analysisId,chainId,control.signal).then(saved=>setResult(saved.result)).catch(e=>{
      if(e.name!=='AbortError') setFailed(true);
    });
    return()=>control.abort();
  },[analysisId,chainId]);
  async function generate() {
    setBusy(true);setFailed(false);setResult(null);
    try {setResult(await api.stageExplain(analysisId,chainId));} catch {setFailed(true);} finally {setBusy(false);}
  }
  const report=result?.analysis_id===analysisId && result.chain_id===chainId && result.status==='available' &&
    result.grounding_status==='validated' && result.report_json?.chain_id===chainId ? result.report_json : null;
  const facts=(items:StageAIFact[])=><ul>{items.map(f=><li key={f.fact_id}><p>{f.description}</p><span className="muted">证据：</span>{f.evidence_refs.map(a=><button key={a} className="text-button" onClick={()=>onEvidence(a)}><StableId value={a}/></button>)}<details><summary>原始字段引用</summary><pre>{JSON.stringify(f.field_refs,null,2)}</pre></details></li>)}</ul>;
  function download(format:'json'|'md') {
    if(!report || !result) return;
    const blob=new Blob([format==='json'?JSON.stringify(report,null,2):result.report_markdown??''],{type:format==='json'?'application/json;charset=utf-8':'text/markdown;charset=utf-8'});
    const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=`${chainId}-ai.${format}`;a.click();URL.revokeObjectURL(url);
  }
  return <section className="stage-ai-report" aria-label="AI 辅助研判">
    <div className="section-heading"><div><h3>AI 辅助研判</h3><p className="muted">解释已有阶段、关联证据与影响；解释信心不代表算法关系置信度。</p></div><button disabled={busy} onClick={generate}>{busy?'正在研判…':report?'重新生成研判':'生成 AI 研判'}</button></div>
    {(failed || result?.status==='unavailable') && <Notice>AI 辅助研判暂不可用</Notice>}
    {report && <><p>{report.chain_summary.summary}</p><p><button onClick={()=>download('json')}>导出研判 JSON</button> <button onClick={()=>download('md')}>导出研判 Markdown</button></p>
      {report.stages.map(s=><details key={s.stage_id}><summary>Stage 行为与危害 · <StableId value={s.stage_id}/></summary>
        <h4>OBSERVED_FACT · 观测事实</h4>{facts(s.observed_facts)}
        <h4>BEHAVIOR_INTERPRETATION · 行为解释</h4><p>{s.behavior_interpretation.description}</p><p className="muted">解释信心：{s.behavior_interpretation.confidence}</p>
        <h4>MISSING_EVIDENCE · 缺失证据</h4><ul>{s.missing_evidence.map(v=><li key={v}>{v}</li>)}</ul>
        <h4>POTENTIAL_IMPACT · 潜在危害</h4><ul>{s.risk_analysis.potential_impact.map(v=><li key={v}>{v}</li>)}</ul>
        <h4>CONFIRMED_IMPACT · 已确认后果</h4>{s.risk_analysis.confirmed_impact.length?facts(s.risk_analysis.confirmed_impact):<p>无证据支持的已确认后果。</p>}
      </details>)}
      <details><summary>已有 Relation 的关联依据</summary>{report.relations.map(r=><article key={r.relation_id}><button className="text-button" onClick={()=>onEvidence(r.relation_id)}><StableId value={r.relation_id}/></button><p>{r.relation_type} · {r.direction_status}</p><p>{r.relation_explanation}</p>{r.supporting_evidence.map(e=><p key={e.claim_id}>{e.description}{e.evidence_refs.map(a=><button className="text-button" key={a} onClick={()=>onEvidence(a)}><StableId value={a}/></button>)}</p>)}<ul>{r.limitations.map(v=><li key={v}>{v}</li>)}</ul></article>)}</details>
      <details><summary>Chain 整体影响与不确定性</summary><h4>主要观测活动</h4>{facts(report.chain_summary.main_observed_activities)}<h4>潜在整体危害</h4><ul>{report.chain_summary.potential_overall_impact.map(v=><li key={v}>{v}</li>)}</ul><h4>已确认整体后果</h4>{report.chain_summary.confirmed_overall_impact.length?facts(report.chain_summary.confirmed_overall_impact):<p>无证据支持的已确认后果。</p>}<h4>不确定性</h4><ul>{report.chain_summary.uncertainties.map(v=><li key={v}>{v}</li>)}</ul></details>
    </>}
  </section>;
}
