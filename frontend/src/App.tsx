import {Component, useEffect, useRef, useState, type ReactNode} from 'react';
import {api} from './api/client';
import {ClipboardPaste, GitBranch, LayoutDashboard, Menu, Waypoints, X} from 'lucide-react';
import Dashboard from './pages/Dashboard';
import IncidentList from './pages/IncidentList';
import IncidentDetail from './pages/IncidentDetail';
import {EvidencePanel} from './components/evidence/EvidencePanel';
import {Notice} from './components/common';
import {CopyId} from './components/ui/copy-id';
import {TraceIcon} from './components/ui/trace-icon';
import {DEFAULT_FILTERS, readLocation, routeHref, routeTitle, type ListFilters, type Route} from './lib/route';
import {loadRecentAnalyses, saveRecentAnalysis} from './lib/recent';
import type {EvidenceSelection} from './types/domain';

type Selection = {kind: 'node' | 'edge'; id: string} | null;

interface RecentItem {analysisId: string; openedAt?: string; createdAt?: string; incidentCount?: number; status?: string}

function Welcome({onOpen}: {onOpen: (analysisId: string) => void}) {
  const [remote,setRemote] = useState<RecentItem[] | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    api.analyses(controller.signal).then(result => {if (!controller.signal.aborted) setRemote(result.items.map(item => ({analysisId:item.analysis_id,createdAt:item.created_at,incidentCount:item.incident_count,status:item.status})));})
      .catch(() => {if (!controller.signal.aborted) setRemote([]);});
    return () => controller.abort();
  },[]);
  const local = loadRecentAnalyses().map(item => ({analysisId:item.analysisId,openedAt:item.openedAt}));
  const recent: RecentItem[] = remote?.length ? remote.slice(0, 5) : local;
  return <div className="welcome">
    <span className="eyebrow">告警 → 安全事件 → 攻击链 → 证据 → AI 研判</span>
    <h1 data-page-title tabIndex={-1}>从碎片告警，回到可核验的调查。</h1>
    <p>粘贴 分析 ID，或通过 演示程序打印的 Web 地址打开已有分析。</p>
    <Notice kind="info">先构建前端，再运行 <code>python scripts/demo.py --analysis-id &lt;ID&gt;</code> 可直接打开真实快照。</Notice>
    <section aria-label="最近打开的分析" className="recent-analyses">
      <h2>最近打开的分析</h2>
      {recent.length ? <ul>{recent.map(item => <li key={item.analysisId}><button onClick={() => onOpen(item.analysisId)} type="button"><CopyId copy={false} label="最近分析 ID" value={item.analysisId}/><span className="muted">{item.incidentCount !== undefined ? `${item.incidentCount.toLocaleString()} 事件` : ''}{item.openedAt ? ` · ${new Date(item.openedAt).toLocaleString('zh-CN')}` : ''}{item.createdAt ? ` · ${new Date(item.createdAt).toLocaleString('zh-CN')}` : ''}</span></button></li>)}</ul> : remote === null ? <p className="muted">正在读取分析列表…</p> : <p className="muted">本机还没有记录。打开一次分析后会出现在这里。</p>}
    </section>
  </div>;
}

function Workspace() {
  const [route,setRoute] = useState<Route>(() => readLocation());
  const [input,setInput] = useState(route.analysisId);
  const [evidence,setEvidence] = useState<EvidenceSelection|null>(null);
  const [revision,setRevision] = useState(0);
  const [menuOpen,setMenuOpen] = useState(false);
  const mainRef = useRef<HTMLElement>(null);
  const menuRef = useRef<HTMLDialogElement>(null);
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  const pendingScroll = useRef<number | null>(null);
  const analysisId = route.analysisId, incidentId = route.incidentId, filters = route.filters;
  const listScrollKey = 'traceback.listScroll.' + analysisId;

  useEffect(() => {
    const handler = () => {
      const next = readLocation();
      setRoute(next);
      setEvidence(null);
    };
    addEventListener('popstate',handler);
    return () => removeEventListener('popstate',handler);
  },[]);
  useEffect(() => {
    setInput(analysisId);
    if (!route.evidenceId) setEvidence(null);
  },[analysisId,incidentId,route.evidenceId]);
  useEffect(() => {
    if (route.evidenceId && incidentId) setEvidence({title: '深链证据', objectId: route.nodeId || route.edgeId || incidentId, alertIds: [route.evidenceId]});
  },[route.evidenceId,incidentId,route.nodeId,route.edgeId]);
  useEffect(() => {document.title = routeTitle(route);},[route]);
  useEffect(() => {if (analysisId) saveRecentAnalysis(analysisId);},[analysisId]);
  useEffect(() => {
    if (!analysisId) return;
    const frame = requestAnimationFrame(() => {
      const heading = mainRef.current?.querySelector<HTMLElement>('[data-page-title]');
      heading?.focus({preventScroll:true});
    });
    return () => cancelAnimationFrame(frame);
  },[analysisId,incidentId]);
  useEffect(() => {
    if (incidentId || pendingScroll.current === null) return;
    const y = pendingScroll.current;
    pendingScroll.current = null;
    requestAnimationFrame(() => window.scrollTo(0,y));
  },[incidentId]);

  // Global keyboard: `/` search, Esc closes/clears, j/k moves through list rows.
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.defaultPrevented || event.metaKey || event.ctrlKey || event.altKey) return;
      const target = event.target as HTMLElement | null;
      const typing = Boolean(target?.closest('input,textarea,select,[contenteditable="true"]'));
      if (event.key === '/' && !typing) {
        event.preventDefault();
        const search = document.querySelector<HTMLInputElement>('[aria-label="搜索当前页"]');
        (search ?? document.getElementById('analysis-input'))?.focus();
        return;
      }
      if (event.key === 'Escape') {
        if (evidence) {setEvidence(null);return;}
        if (typing) {(target as HTMLInputElement)?.blur();if (filters.q) replaceUrl({...route,filters:{...filters,q:'',page:1}});}
        return;
      }
      if (!typing && !incidentId && (event.key === 'j' || event.key === 'k')) {
        const rows = [...document.querySelectorAll<HTMLElement>('#incident-list tbody tr')];
        if (!rows.length) return;
        const current = rows.indexOf(document.activeElement as HTMLElement);
        const next = rows[Math.max(0,Math.min(rows.length - 1, current < 0 ? 0 : current + (event.key === 'j' ? 1 : -1)))];
        event.preventDefault();
        next.focus();
      }
    };
    addEventListener('keydown',onKeyDown);
    return () => removeEventListener('keydown',onKeyDown);
  },[evidence,filters,incidentId,route]);

  function replaceUrl(next: Route) {history.replaceState({},'',routeHref(next));setRoute(next);}
  function navigate(a: string, i = '', nextFilters: ListFilters = filters, deep: Partial<Pick<Route,'nodeId'|'edgeId'|'evidenceId'|'timelinePage'>> = {}) {
    if (!incidentId && i) {try {sessionStorage.setItem(listScrollKey, String(window.scrollY));} catch { /* storage unavailable */ }}
    const next: Route = {analysisId: a, incidentId: i, filters: nextFilters, nodeId: deep.nodeId ?? '', edgeId: deep.edgeId ?? '', evidenceId: deep.evidenceId ?? '', timelinePage: deep.timelinePage ?? 1};
    history.pushState({},'',routeHref(next));
    setRoute(next);
    setEvidence(null);
    window.scrollTo(0,0);
  }
  function openLinkedSelection(selection: Selection) {
    if (!incidentId) return;
    replaceUrl({...route,nodeId: selection?.kind === 'node' ? selection.id : '',edgeId: selection?.kind === 'edge' ? selection.id : ''});
  }
  function openEvidence(selection: EvidenceSelection) {setEvidence(selection);}
  function closeEvidence() {setEvidence(null);if (route.evidenceId) replaceUrl({...route,evidenceId:''});}
  function setTimelinePage(page: number) {replaceUrl({...route,timelinePage:page});}
  function openMenu() {setMenuOpen(true);requestAnimationFrame(() => {try {menuRef.current?.showModal();} catch { /* jsdom has no showModal */ }});}
  function closeMenu() {try {menuRef.current?.close();} catch { /* noop */ }setMenuOpen(false);menuButtonRef.current?.focus();}
  async function pasteAnalysis() {try {const text = (await navigator.clipboard?.readText())?.trim();if (text) setInput(text);} catch { /* clipboard stays optional */ }}
  function backToQueue() {
    try {pendingScroll.current = Number(sessionStorage.getItem(listScrollKey) ?? 0) || 0;} catch {pendingScroll.current = 0;}
    navigate(analysisId);
  }

  const homeHref = routeHref({...route,incidentId:'',nodeId:'',edgeId:'',evidenceId:'',timelinePage:1});
  const activeList = !incidentId;
  return <div className="app">
    <a className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-card focus:px-4 focus:py-2 focus:text-sm focus:text-foreground focus:shadow-lg focus:ring-2 focus:ring-ring" href="#main-content">跳到主要内容</a>
    <aside className="sidebar">
      <a className="brand" href={analysisId ? homeHref : '/'} onClick={event => {if (!analysisId) return;event.preventDefault();navigate(analysisId,'',filters);}}>
        <span className="brand-mark"><TraceIcon icon={Waypoints} size={19} /></span>
        <span>TraceBack<small>智溯 / 安全研判工作台</small></span>
      </a>
      <button aria-expanded={menuOpen} aria-label="打开导航菜单" className="mobile-nav-button" onClick={openMenu} ref={menuButtonRef} type="button"><TraceIcon icon={Menu} size={20}/></button>
      <nav aria-label="调查流程">
        <p className="sidebar-label">调查流程</p>
        <button aria-current={activeList ? 'page' : undefined} className={'nav-item flex items-center gap-2 ' + (activeList ? 'active' : '')} onClick={() => analysisId && navigate(analysisId)} type="button"><TraceIcon icon={LayoutDashboard} size={15}/>分析工作台</button>
        <button aria-current={incidentId ? 'page' : undefined} className={'nav-item flex items-center gap-2 ' + (incidentId ? 'active' : '')} onClick={() => analysisId && navigate(analysisId,'',{...filters,page:1,kind:'has_chain'})} title="查看有向攻击链事件" type="button"><TraceIcon icon={GitBranch} size={15}/>安全事件 / 证据研判</button>
      </nav>
      <div className="principle"><b>算法关联与重构</b><span>告警事实与证据</span><span>AI 解释与研判</span></div>
      <p className="sidebar-footer">离线快照 · 可核验证据<br/>原始告警不等于已确认攻击</p>
      <dialog aria-label="调查流程导航" className="mobile-nav" onCancel={closeMenu} onClose={() => setMenuOpen(false)} ref={menuRef}>
        <div className="mobile-nav-heading"><strong>调查流程</strong><button aria-label="关闭导航菜单" onClick={closeMenu} type="button"><TraceIcon icon={X} size={18}/></button></div>
        <button aria-current={activeList ? 'page' : undefined} className={'nav-item flex items-center gap-2 ' + (activeList ? 'active' : '')} onClick={() => {closeMenu();analysisId && navigate(analysisId);}} type="button"><TraceIcon icon={LayoutDashboard} size={16}/>分析工作台</button>
        <button aria-current={incidentId ? 'page' : undefined} className={'nav-item flex items-center gap-2 ' + (incidentId ? 'active' : '')} onClick={() => {closeMenu();analysisId && navigate(analysisId,'',{...filters,page:1,kind:'has_chain'});}} type="button"><TraceIcon icon={GitBranch} size={16}/>安全事件 / 证据研判</button>
        <p className="sidebar-footer-mobile">离线快照 · 可核验证据<br/>原始告警不等于已确认攻击</p>
      </dialog>
    </aside>
    <div className="workspace">
      <header className="topbar">
        <span className="topbar-context">安全运营</span>
        <form onSubmit={event => {event.preventDefault();navigate(input.trim(),'',DEFAULT_FILTERS);}}>
          <label className="sr-only" htmlFor="analysis-input">分析 ID</label>
          <input aria-describedby="analysis-hint" id="analysis-input" value={input} placeholder="粘贴 ana_… 稳定 ID" onChange={event => setInput(event.target.value)} required pattern="ana_[a-f0-9]{64}" />
          <span className="analysis-hint" id="analysis-hint">ana_ + 64 位十六进制</span>
          <button aria-label="从剪贴板粘贴分析 ID" disabled={!navigator.clipboard?.readText} onClick={pasteAnalysis} type="button"><TraceIcon icon={ClipboardPaste} size={14}/><span className="paste-label">粘贴</span></button>
          <button type="submit">打开分析</button>
        </form>
        {analysisId && <span className="analysis-chip">当前分析 <CopyId label="当前分析 ID" value={analysisId}/></span>}
      </header>
      <main aria-label="主要内容" id="main-content" ref={mainRef} tabIndex={-1}>
        <PageBoundary key={analysisId + ':' + incidentId}>
          {!analysisId ? <Welcome onOpen={id => navigate(id)}/> : incidentId ? <IncidentDetail
            analysisId={analysisId}
            incidentId={incidentId}
            initialEdgeId={route.edgeId}
            initialNodeId={route.nodeId}
            key={analysisId+incidentId}
            onBack={backToQueue}
            onEvidence={openEvidence}
            onGenerated={() => setRevision(r => r+1)}
            onSelectionChange={openLinkedSelection}
            onTimelinePage={setTimelinePage}
            timelinePage={route.timelinePage}
          /> : <><Dashboard analysisId={analysisId}/><IncidentList analysisId={analysisId} filters={filters} revision={revision} onFilters={next => navigate(analysisId,'',next)} onOpen={id => navigate(analysisId,id)}/></>}
        </PageBoundary>
      </main>
    </div>
    {evidence && <EvidencePanel analysisId={analysisId} key={analysisId+evidence.objectId+evidence.alertIds.join(',')} onClose={closeEvidence} selection={evidence}/>}
  </div>;
}

class PageBoundary extends Component<{children:ReactNode},{failed:boolean}> {
  state = {failed:false};
  static getDerivedStateFromError(){return {failed:true};}
  componentDidCatch(){document.title = '页面暂时无法显示 · TraceBack';}
  render(){
    if (!this.state.failed) return this.props.children;
    return <div className="fatal-error">
      <h1 tabIndex={-1}>页面暂时无法显示</h1>
      <Notice kind="error">当前视图渲染失败。请刷新后重新打开分析；设备分析结果仍保存在后端快照中。</Notice>
      <div className="flex flex-wrap gap-2">
        <button onClick={() => {this.setState({failed:false});window.scrollTo(0,0);}} type="button">重试当前页面</button>
        <button onClick={() => location.reload()} type="button">重新加载</button>
      </div>
    </div>;
  }
}

export default function App() {return <Workspace/>;}
