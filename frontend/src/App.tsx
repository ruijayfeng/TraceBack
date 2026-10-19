import {Component, useEffect, useState, type ReactNode} from 'react';
import Dashboard from './pages/Dashboard';
import IncidentList, {type ListFilters} from './pages/IncidentList';
import IncidentDetail from './pages/IncidentDetail';
import {EvidencePanel} from './components/evidence/EvidencePanel';
import {Notice} from './components/common';
import type {EvidenceSelection} from './types/domain';

function readLocation() {
  const p = new URLSearchParams(location.search);
  return {analysisId:p.get('analysis_id') ?? '',incidentId:p.get('incident_id') ?? '',filters:{page:Math.max(1,Number(p.get('page')) || 1),kind:p.get('kind') ?? 'all',sort:p.get('sort') ?? 'time',severity:p.get('severity') ?? ''}};
}
function Workspace() {
  const [route,setRoute] = useState(readLocation), [input,setInput] = useState(route.analysisId), [evidence,setEvidence] = useState<EvidenceSelection|null>(null), [revision,setRevision] = useState(0);
  useEffect(() => {const handler = () => {setRoute(readLocation());setEvidence(null);}; addEventListener('popstate',handler); return () => removeEventListener('popstate',handler);},[]);
  useEffect(() => {setInput(route.analysisId);setEvidence(null);},[route.analysisId,route.incidentId]);
  function navigate(a: string, i = '', filters: ListFilters = route.filters) {
    const p = new URLSearchParams({analysis_id:a}); if(i) p.set('incident_id',i); if(filters.page !== 1) p.set('page',String(filters.page)); if(filters.kind !== 'all') p.set('kind',filters.kind); if(filters.sort !== 'time') p.set('sort',filters.sort); if(filters.severity) p.set('severity',filters.severity);
    history.pushState({},'',location.pathname+'?'+p); setRoute(readLocation());setEvidence(null);window.scrollTo(0,0);
  }
  return <div className="app"><aside className="sidebar"><a className="brand" href="/">↗ <span>TraceBack<small>智溯 / 安全研判工作台</small></span></a><p className="sidebar-label">调查流程</p><button className={!route.incidentId ? 'nav-item active' : 'nav-item'} onClick={() => route.analysisId && navigate(route.analysisId)}>◫ 分析工作台</button><div className={'nav-item '+(route.incidentId ? 'active' : '')}>⌁ 安全事件 / 证据研判</div><div className="principle"><b>算法关联与重构</b><span>告警事实与证据</span><span>AI 解释与研判</span></div><p className="sidebar-footer">离线快照 · 可核验证据<br/>原始告警不等于已确认攻击</p></aside><div className="workspace"><header className="topbar"><span>安全运营</span><form onSubmit={e => {e.preventDefault();navigate(input.trim(), '',{page:1,kind:'all',sort:'time',severity:''});}}><label htmlFor="analysis-input">分析 ID</label><input id="analysis-input" value={input} placeholder="粘贴 ana_… 稳定 ID" onChange={e => setInput(e.target.value)} required pattern="ana_[a-f0-9]{64}"/><button type="submit">打开分析</button></form></header><main>
    {!route.analysisId ? <div className="welcome"><span className="eyebrow">告警 → 安全事件 → 攻击链 → 证据 → AI 研判</span><h1>从碎片告警，回到可核验的调查。</h1><p>粘贴 分析 ID，或通过 演示程序打印的 Web 地址打开已有分析。</p><Notice kind="info">先构建前端，再运行 <code>python scripts/demo.py --analysis-id &lt;ID&gt;</code> 可直接打开真实快照。</Notice></div> : route.incidentId ? <IncidentDetail key={route.analysisId+route.incidentId} analysisId={route.analysisId} incidentId={route.incidentId} onEvidence={setEvidence} onBack={() => navigate(route.analysisId)} onGenerated={() => setRevision(r => r+1)}/> : <><Dashboard analysisId={route.analysisId}/><IncidentList analysisId={route.analysisId} filters={route.filters} revision={revision} onFilters={filters => navigate(route.analysisId,'',filters)} onOpen={id => navigate(route.analysisId,id)}/></>}
  </main></div>{evidence && <><button className="drawer-backdrop" aria-label="关闭证据遮罩" onClick={() => setEvidence(null)}/><EvidencePanel key={route.analysisId+evidence.objectId+evidence.alertIds.join(',')} analysisId={route.analysisId} selection={evidence} onClose={() => setEvidence(null)}/></>}</div>;
}
class ErrorBoundary extends Component<{children:ReactNode},{failed:boolean}> {state = {failed:false};static getDerivedStateFromError(){return {failed:true};}render(){return this.state.failed ? <div className="fatal-error"><h1>页面暂时无法显示</h1><Notice kind="error">请刷新后重新打开分析。设备分析结果仍保存在后端快照中。</Notice><button onClick={() => location.reload()}>重新加载</button></div> : this.props.children;}}
export default function App() {return <ErrorBoundary><Workspace/></ErrorBoundary>;}
