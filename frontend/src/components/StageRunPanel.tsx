import {useEffect, useRef, useState, type ReactNode} from 'react';
import {api} from '../api/client';
import {Icon} from './Icon';
import {Notice, StableId, Time} from './common';
import type {StageCatalog, StageRun, StageUpload} from '../types/stageAnalysis';
import '../styles/stageRuns.css';

const active=(run:StageRun)=>['QUEUED','VALIDATING','RUNNING'].includes(run.status);
const statusNames:Record<string,string>={QUEUED:'分析排队中',VALIDATING:'正在校验输入',RUNNING:'正在分析',SUCCEEDED:'分析成功',FAILED:'分析失败'};
const trackedKey='traceback:last-stage-run',pendingKey='traceback:pending-stage-run';
function remembered(key:string){try{return localStorage.getItem(key)??'';}catch{return '';}}
function remember(key:string,value:string){try{if(value)localStorage.setItem(key,value);else localStorage.removeItem(key);}catch{/* Server history remains authoritative. */}}

function ImportDrawer({children,onClose}:{children:ReactNode;onClose:()=>void}){
  const dialog=useRef<HTMLDialogElement>(null);
  useEffect(()=>{
    const element=dialog.current!,previous=document.activeElement as HTMLElement|null;
    const overflow=document.body.style.overflow,padding=document.body.style.paddingRight;
    const gap=window.innerWidth-document.documentElement.clientWidth;
    document.body.style.overflow='hidden';if(gap>0)document.body.style.paddingRight=`${gap}px`;
    if(element.showModal)element.showModal();else element.setAttribute('open','');
    return()=>{element.close?.();document.body.style.overflow=overflow;document.body.style.paddingRight=padding;previous?.focus({preventScroll:true});};
  },[]);
  return <dialog ref={dialog} className="run-drawer" aria-labelledby="import-title" onCancel={e=>{e.preventDefault();onClose();}} onClick={e=>{
    if(e.target!==e.currentTarget)return;const rect=e.currentTarget.getBoundingClientRect();
    if(e.clientX<rect.left||e.clientX>rect.right||e.clientY<rect.top||e.clientY>rect.bottom)onClose();
  }}><header className="run-drawer-heading"><div><span className="eyebrow">分析操作</span><h2 id="import-title">导入告警与分析</h2><p>关闭面板后，已登记的任务会继续在后台运行。</p></div><button aria-label="关闭导入面板" onClick={onClose} autoFocus>×</button></header><div className="run-drawer-content">{children}</div></dialog>;
}

function RunDetails({run,onResult}:{run:StageRun;onResult:()=>void}){
  return <div className="run-details" data-run-id={run.run_id}>
    <div className="section-heading"><h3>{statusNames[run.status]}</h3><StableId value={run.run_id}/></div>
    <p>{run.filename} · {run.input_count} 条告警</p>
    <p>当前阶段：{run.current_stage??'等待执行'} · 退出码：{run.exit_code??'—'} · {run.duration_seconds!==null?`耗时 ${run.duration_seconds.toFixed(2)} 秒`:active(run)&&run.started_at?`已运行 ${Math.max(0,(Date.now()-Date.parse(run.started_at))/1000).toFixed(1)} 秒`:'尚未开始'}</p>
    <p>创建：<Time value={run.created_at}/></p>
    {run.started_at&&<p>开始：<Time value={run.started_at}/>{run.finished_at&&<> · 完成：<Time value={run.finished_at}/></>}</p>}
    {(run.failure_reason||run.unavailable_reason)&&<Notice kind="error">失败阶段：{run.failed_stage??'产物检查'}；{run.failure_reason??run.unavailable_reason}</Notice>}
    <ol className="run-stages">{run.stages.map(stage=><li key={stage.stage} data-status={stage.status}>{stage.name}<span>{({PENDING:'待执行',RUNNING:'执行中',COMPLETED:'已完成',FAILED:'失败'} as Record<string,string>)[stage.status]}</span></li>)}</ol>
    {run.result_available&&<div className="run-result"><p role="status">产物检查通过，本次分析结果已就绪。</p><button className="primary" onClick={onResult}>查看本次结果</button></div>}
    <details open={active(run)||run.status==='FAILED'}><summary>运行日志</summary><pre className="run-log">{run.recent_log||'尚无 CLI 日志。'}</pre>{run.recent_log&&<a href={`/api/v1/stage-runs/${run.run_id}/log`} download>下载完整日志</a>}</details>
  </div>;
}

// This controller stays mounted when the drawer closes. Validation and polling
// have one owner across the workspace, including the records page.
export default function StageRunPanel({catalog,selectedId,view,onSelect,onRuns}:{catalog:StageCatalog|null;selectedId:string;view:string;onSelect:(id:string)=>void;onRuns:(runs:StageRun[])=>void}){
  const [upload,setUpload]=useState<StageUpload|null>(null),[runs,setRuns]=useState<StageRun[]>([]);
  const [busy,setBusy]=useState(''),[error,setError]=useState(''),[historyError,setHistoryError]=useState('');
  const [open,setOpen]=useState(false),[trackedId,setTrackedId]=useState(()=>remembered(trackedKey));
  const [pendingId,setPendingId]=useState(()=>remembered(pendingKey)),[inspectId,setInspectId]=useState('');
  const callbacks=useRef({onRuns,onSelect});callbacks.current={onRuns,onSelect};
  const mounted=useRef(true),version=useRef(0),runList=useRef(runs);runList.current=runs;
  const selectedRun=runs.find(run=>run.run_id===selectedId),tracked=runs.find(run=>run.run_id===trackedId);
  const current=runs.find(run=>run.run_id===inspectId),latestActive=runs.find(active);
  const task=latestActive??selectedRun??tracked;
  const baselineItems=catalog?.items.filter(item=>!runs.some(run=>run.run_id===item.analysis_id))??[];
  const choices=[...runs.map(run=>({id:run.run_id,label:`${run.filename} · ${run.input_count} 条 · ${run.unavailable_reason?'结果不可用':statusNames[run.status]} · ${run.run_id.slice(4,12)}`})),...baselineItems.map(item=>({id:item.analysis_id,label:`${item.official?'正式验收基线':item.source_stage===9?'既有重构快照':'既有 Assembly 快照'} · ${item.input_count} 条 · ${item.analysis_id.slice(4,12)}`}))];
  const selectedLabel=choices.find(item=>item.id===selectedId)?.label;
  useEffect(()=>{
    mounted.current=true;const controller=new AbortController();let timer:ReturnType<typeof setTimeout>;
    async function refresh(){
      const before=version.current;
      try{const result=await api.stageRuns(controller.signal);if(!controller.signal.aborted&&before===version.current){setRuns(result.items);callbacks.current.onRuns(result.items);setHistoryError('');}}
      catch(e){if(!controller.signal.aborted)setHistoryError((e as Error).message);}
      if(!controller.signal.aborted)timer=setTimeout(refresh,2000);
    }
    void refresh();return()=>{mounted.current=false;controller.abort();clearTimeout(timer);};
  },[]);
  useEffect(()=>{
    if(!pendingId)return;const completed=runs.find(run=>run.run_id===pendingId);
    if(completed?.result_available){callbacks.current.onSelect(pendingId);setPendingId('');remember(pendingKey,'');}
    else if(completed?.status==='FAILED'){setPendingId('');remember(pendingKey,'');}
  },[runs,pendingId]);
  function show(runId?:string){setInspectId(runId??task?.run_id??selectedId??'');setOpen(true);}
  function select(id:string){callbacks.current.onSelect(id);const run=runs.find(item=>item.run_id===id);if(run&&!run.result_available)show(id);}
  async function importFile(file:File){
    setUpload(null);setInspectId('');setError('');setBusy('正在上传文件…');
    try{const result=await api.stageUpload(file,undefined,()=>{if(mounted.current)setBusy('上传完成，正在校验…');});if(mounted.current)setUpload(result);}
    catch(e){if(mounted.current)setError((e as Error).message);}
    finally{if(mounted.current)setBusy('');}
  }
  async function start(){
    if(!upload||upload.validation.status!=='VALID')return;setError('');setBusy('正在登记任务…');
    try{
      const run=await api.stageStart(upload.upload_id);if(!mounted.current)return;
      version.current++;const next=[run,...runList.current.filter(item=>item.run_id!==run.run_id)];
      setRuns(next);callbacks.current.onRuns(next);setUpload(null);setInspectId(run.run_id);
      setTrackedId(run.run_id);remember(trackedKey,run.run_id);setPendingId(run.run_id);remember(pendingKey,run.run_id);
    }catch(e){if(mounted.current)setError((e as Error).message);}
    finally{if(mounted.current)setBusy('');}
  }
  const openResult=(id:string)=>{callbacks.current.onSelect(id);setOpen(false);};
  return <section className="run-controls" aria-label="分析批次与操作">
    <div className={'workspace-titlebar'+(view==='overview'?'':' run-utilitybar')}>
      {view==='overview'?<div><h1>安全运营态势总览</h1><p>多源告警关联、攻击阶段分析与证据追溯。</p></div>:<span className="run-workspace-label"><Icon name="layers"/>分析工作台</span>}
      <div className="run-title-actions">
        {task?<button className={'run-task-status status-'+(task.unavailable_reason?'failed':task.status.toLowerCase())} onClick={()=>show(task.run_id)} title={`${task.filename} · ${task.current_stage??statusNames[task.status]}`}><span className="status-dot"/>{task.unavailable_reason?'结果不可用':statusNames[task.status]}{latestActive&&<span> · 后台运行中</span>}</button>:<span className="run-ready">{selectedId?'分析结果已就绪':'等待导入告警'}</span>}
        <button className="primary run-import-button" onClick={()=>show()}><Icon name="file"/>导入告警</button>
        {view==='overview'&&<button className="run-refresh" aria-label="刷新工作台" onClick={()=>location.reload()}><Icon name="refresh"/></button>}
      </div>
    </div>
    <div className="run-batch-toolbar"><label htmlFor="analysis-batch">当前分析批次</label><select id="analysis-batch" aria-label="历史分析" title={selectedLabel??selectedId} value={selectedId} onChange={e=>select(e.target.value)}><option value="" disabled>选择分析批次</option>{selectedId&&!selectedLabel&&<option value={selectedId}>{selectedId.slice(0,20)} · 正在识别</option>}{choices.map(item=><option key={item.id} value={item.id}>{item.label}</option>)}</select><span className="run-batch-id" title={selectedId}>{selectedId?selectedId.slice(4,12):'尚无分析'}</span></div>
    {historyError&&<Notice kind="error">任务状态暂不可读取：{historyError}</Notice>}
    {view==='records'&&<section className="panel run-history-table" aria-label="历史分析任务"><div className="section-heading"><h2>历史分析任务</h2><span className="muted">{runs.length} 次导入分析 · {baselineItems.length} 个既有快照</span></div><div className="table-scroll"><table><thead><tr><th>批次</th><th>文件名</th><th>告警数</th><th>分析时间</th><th>状态</th><th>操作</th></tr></thead><tbody>{runs.map(run=><tr key={run.run_id}><td><StableId value={run.run_id}/></td><td>{run.filename}</td><td>{run.input_count}</td><td><Time value={run.created_at}/></td><td>{statusNames[run.status]} · {run.result_available?'结果可用':run.unavailable_reason?'结果不可用':'结果未就绪'}</td><td><button className="text-button" onClick={()=>run.result_available?openResult(run.run_id):show(run.run_id)}>{run.result_available?'查看结果':'查看状态与日志'}</button>{run.result_available&&<button className="text-button" onClick={()=>show(run.run_id)}>运行详情</button>}</td></tr>)}</tbody></table></div>{!runs.length&&<Notice>尚无导入分析任务，既有快照可通过上方批次选择器打开。</Notice>}</section>}
    {open&&<ImportDrawer onClose={()=>setOpen(false)}><section className="run-upload-section" aria-label="告警导入与分析任务"><h3>选择原生告警文件</h3><p className="run-upload-hint">JSONL · UTF-8 · 最大 16 MiB。每行一条符合现有来源契约的原生告警。</p>
      <label className="run-file">选择告警文件<input aria-label="选择告警文件" type="file" accept=".jsonl" disabled={!!busy} onChange={e=>{const file=e.target.files?.[0];if(file)void importFile(file);e.target.value='';}}/></label>
      {!busy&&!upload&&!current&&!error&&<p className="run-empty-hint">等待选择文件，上传后将自动检查字段契约。</p>}
      {busy&&<Notice kind="loading">{busy}</Notice>}{error&&<Notice kind="error">操作失败：{error}</Notice>}
      {upload&&<div className="run-validation" aria-live="polite"><b>{upload.filename}</b><p>{upload.size_bytes} 字节 · 共 {upload.validation.total_count} 条 · 通过 {upload.validation.valid_count} 条 · 失败 {upload.validation.invalid_count} 条 · {upload.validation.status==='VALID'?'校验通过':'校验失败'}</p>
        {upload.validation.errors.length>0?<details open><summary>校验错误（{upload.validation.errors.length} 项）</summary><div className="table-scroll"><table><thead><tr><th>行号</th><th>字段</th><th>原因</th></tr></thead><tbody>{upload.validation.errors.slice(0,100).map((e,i)=><tr key={i}><td>{e.line}</td><td>{e.field}</td><td>{e.reason}</td></tr>)}</tbody></table></div><a href={`/api/v1/stage-runs/uploads/${upload.upload_id}/errors`} download>下载全部校验错误</a></details>:<p className="run-valid-hint">校验通过，等待开始分析。</p>}
      </div>}
      <button className="primary run-start-button" disabled={!!busy||upload?.validation.status!=='VALID'} onClick={()=>void start()}>开始分析</button>
    </section>{current&&<RunDetails run={current} onResult={()=>openResult(current.run_id)}/>}</ImportDrawer>}
  </section>;
}
