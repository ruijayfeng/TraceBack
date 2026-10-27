import {Component, useEffect, useState, type ReactNode} from 'react';
import Dashboard from './pages/Dashboard';
import IncidentList, {type ListFilters} from './pages/IncidentList';
import IncidentDetail from './pages/IncidentDetail';
import {EvidencePanel} from './components/evidence/EvidencePanel';
import {Notice} from './components/common';
import type {EvidenceSelection} from './types/domain';
import StageWorkbench from './pages/StageWorkbench';
import OverviewContainer from './pages/Overview/OverviewContainer';
import {api} from './api/client';
import {useResource} from './api/hooks';
import {Icon} from './components/Icon';
import StageRunPanel from './components/StageRunPanel';
import type {StageRun} from './types/stageAnalysis';

export const modules = [{id:'overview',label:'态势总览'}, {id:'alerts',label:'安全告警'}, {id:'scenes',label:'攻击场景'}, {id:'stages',label:'攻击链'}, {id:'evidence',label:'证据追溯'}, {id:'records',label:'分析记录'}];

function readLocation() {
  const p = new URLSearchParams(location.search);
  return {view:p.get('view') ?? '',chainId:p.get('chain_id') ?? '',analysisId:p.get('analysis_id') ?? '',stageView:p.get('view') === 'stages',incidentId:p.get('incident_id') ?? '',filters:{page:Math.max(1,Number(p.get('page')) || 1),kind:p.get('kind') ?? 'all',sort:p.get('sort') ?? 'time',severity:p.get('severity') ?? ''}};
}
function Workspace() {
  const [route,setRoute] = useState(readLocation), [evidence,setEvidence] = useState<EvidenceSelection|null>(null), [revision,setRevision] = useState(0);
  const catalog = useResource(signal => api.stageCatalog(signal), []);
  const [stageRuns,setStageRuns]=useState<StageRun[]>([]);
  const currentRun=stageRuns.find(run=>run.run_id===route.analysisId);
  // Landing view: 态势总览 is the default; StageWorkbench opens on explicit
  // view=stages; a legacy incident analysis opens when a non-stage analysis_id
  // is supplied (fallback to the old workbench).
  const isStageAnalysis = !!route.analysisId && (!!currentRun || !!catalog.data?.items?.some(item => item.analysis_id === route.analysisId));
  const moduleMode = modules.some(m => m.id === route.view && m.id !== 'stages');
  const overviewMode = !route.view && !route.analysisId || route.view === 'overview';
  const stageMode = !moduleMode && (route.stageView || isStageAnalysis);
  const activeModule = overviewMode ? 'overview' : stageMode ? 'stages' : moduleMode ? route.view : '';
  const pageTitle = modules.find(m => m.id === activeModule)?.label ?? '历史分析';
  useEffect(() => {const handler = () => {setRoute(readLocation());setEvidence(null);}; addEventListener('popstate',handler); return () => removeEventListener('popstate',handler);},[]);
  useEffect(() => {setEvidence(null);},[route.analysisId,route.incidentId]);
  function navigate(a: string, i = '', filters: ListFilters = route.filters) {
    const p = new URLSearchParams({analysis_id:a}); if(i) p.set('incident_id',i); if(filters.page !== 1) p.set('page',String(filters.page)); if(filters.kind !== 'all') p.set('kind',filters.kind); if(filters.sort !== 'time') p.set('sort',filters.sort); if(filters.severity) p.set('severity',filters.severity);
    history.pushState({},'',location.pathname+'?'+p); setRoute(readLocation());setEvidence(null);window.scrollTo(0,0);
  }
  function openOverview() {
    history.pushState({},'',location.pathname+'?'); setRoute(readLocation());setEvidence(null);window.scrollTo(0,0);
  }
  function enterStage(analysisId: string, chainId = '') {
    const p = new URLSearchParams({view:'stages', analysis_id: analysisId});
    if(chainId) p.set('chain_id',chainId);
    history.pushState({},'',location.pathname+'?'+p); setRoute(readLocation());setEvidence(null);window.scrollTo(0,0);
  }
  function selectAnalysis(analysisId: string) {
    const view=activeModule && activeModule!=='records'?activeModule:'overview';
    const p=new URLSearchParams({view,analysis_id:analysisId});
    history.pushState({},'',location.pathname+'?'+p);setRoute(readLocation());setEvidence(null);window.scrollTo(0,0);
  }
  function openModule(view: string, query = '') {
    const p = new URLSearchParams();
    p.set('view',view);
    const identity=route.analysisId || catalog.data?.default_analysis_id;
    if(identity && (activeModule || isStageAnalysis || !route.analysisId)) p.set('analysis_id',identity);
    if(query) p.set('q',query);
    history.pushState({},'',location.pathname+'?'+p);setRoute(readLocation());setEvidence(null);window.scrollTo(0,0);
  }
  return <div className="app soc-app"><div className="workspace"><header className="soc-header"><div className="soc-header-inner"><a className="soc-brand" href="/" onClick={e => {e.preventDefault();openOverview();}}><span className="brand-mark"><Icon name="shield"/></span>TraceBack</a><div className="soc-breadcrumb">安全运营中心 <span>/</span> <b>{pageTitle}</b></div><div className="soc-header-status"><span className="status-dot"/>离线分析快照<span className="user-avatar">T</span></div></div><nav className="module-nav" aria-label="功能模块">{modules.map(m=><a key={m.id} href={m.id==='overview'?'/?view=overview':'/?view='+m.id} aria-current={activeModule===m.id?'page':undefined} onClick={e=>{if(e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;e.preventDefault();openModule(m.id);}}>{m.label}</a>)}</nav></header><main className={stageMode?'soc-main chain-main':'soc-main'}>
    <StageRunPanel catalog={catalog.data} selectedId={route.analysisId || catalog.data?.default_analysis_id || ''} view={activeModule} onSelect={selectAnalysis} onRuns={setStageRuns}/>
    {currentRun && !currentRun.result_available ? <Notice kind={currentRun.status==='FAILED' || currentRun.unavailable_reason?'error':undefined}>本次结果尚不可用：{currentRun.failure_reason || currentRun.unavailable_reason || '任务尚未完成'}。点击任务状态查看进度与日志。</Notice>
    : overviewMode || moduleMode ? <OverviewContainer key={route.analysisId || catalog.data?.default_analysis_id} catalog={catalog} view={activeModule} analysisId={route.analysisId} onNavigate={openModule} onOpenStage={enterStage}/>
    : stageMode ? <StageWorkbench key={route.analysisId} analysisId={route.analysisId} catalog={catalog.data} catalogError={catalog.error}/>
    : catalog.loading ? <Notice kind="loading">正在识别分析记录…</Notice> : route.incidentId ? <IncidentDetail key={route.analysisId+route.incidentId} analysisId={route.analysisId} incidentId={route.incidentId} onEvidence={setEvidence} onBack={() => navigate(route.analysisId)} onGenerated={() => setRevision(r => r+1)}/> : <><Dashboard analysisId={route.analysisId}/><IncidentList analysisId={route.analysisId} filters={route.filters} revision={revision} onFilters={filters => navigate(route.analysisId,'',filters)} onOpen={id => navigate(route.analysisId,id)}/></>}
  </main></div>{evidence && <><button className="drawer-backdrop" aria-label="关闭证据遮罩" onClick={() => setEvidence(null)}/><EvidencePanel key={route.analysisId+evidence.objectId+evidence.alertIds.join(',')} analysisId={route.analysisId} selection={evidence} onClose={() => setEvidence(null)}/></>}</div>;
}
class ErrorBoundary extends Component<{children:ReactNode},{failed:boolean}> {state = {failed:false};static getDerivedStateFromError(){return {failed:true};}render(){return this.state.failed ? <div className="fatal-error"><h1>页面暂时无法显示</h1><Notice kind="error">请刷新后重新打开分析。设备分析结果仍保存在后端快照中。</Notice><button onClick={() => location.reload()}>重新加载</button></div> : this.props.children;}}
export default function App() {return <ErrorBoundary><Workspace/></ErrorBoundary>;}
