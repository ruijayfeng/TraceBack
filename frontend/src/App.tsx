import {Component, useEffect, useRef, useState, type ReactNode} from 'react';
import {api} from './api/client';
import {CircleHelp, ClipboardPaste, GitBranch, LayoutDashboard, Menu, Search, Waypoints, X} from 'lucide-react';
import Dashboard from './pages/Dashboard';
import IncidentList from './pages/IncidentList';
import IncidentDetail from './pages/IncidentDetail';
import Welcome from './pages/Welcome';
import {EvidencePanel} from './components/evidence/EvidencePanel';
import {Notice} from './components/common';
import {Button} from './components/ui/button';
import {Dialog, DialogDescription, DialogFooter, DialogHeader, DialogPopup, DialogTitle} from './components/ui/dialog';
import {CopyId} from './components/ui/copy-id';
import {Kbd} from './components/ui/kbd';
import {TraceIcon} from './components/ui/trace-icon';
import {DEFAULT_FILTERS, readLocation, routeHref, routeTitle, type ListFilters, type Route} from './lib/route';
import {loadRecentAnalyses, saveRecentAnalysis} from './lib/recent';
import type {EvidenceSelection} from './types/domain';

type Selection = {kind: 'node' | 'edge'; id: string} | null;

function Workspace() {
  const [route,setRoute] = useState<Route>(() => readLocation());
  const [input,setInput] = useState(route.analysisId);
  const [evidence,setEvidence] = useState<EvidenceSelection|null>(null);
  const [revision,setRevision] = useState(0);
  const [menuOpen,setMenuOpen] = useState(false);
  const [helpOpen,setHelpOpen] = useState(false);
  const [online,setOnline] = useState(() => typeof navigator === 'undefined' ? true : navigator.onLine);
  const mainRef = useRef<HTMLElement>(null);
  const menuRef = useRef<HTMLDialogElement>(null);
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  const pendingScroll = useRef<number | null>(null);
  const analysisId = route.analysisId, incidentId = route.incidentId, filters = route.filters;
  const listScrollKey = 'traceback.listScroll.' + analysisId;

  useEffect(() => {
    const goOnline = () => setOnline(true);
    const goOffline = () => setOnline(false);
    addEventListener('online', goOnline);
    addEventListener('offline', goOffline);
    return () => {removeEventListener('online', goOnline);removeEventListener('offline', goOffline);};
  },[]);
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
      const target = event.target instanceof HTMLElement ? event.target : null;
      const typing = Boolean(target?.closest('input,textarea,select,[contenteditable="true"]'));
      if (event.key === '/' && !typing) {
        event.preventDefault();
        const search = document.querySelector<HTMLInputElement>('[aria-label="搜索当前页"]');
        (search ?? document.getElementById('analysis-input'))?.focus();
        return;
      }
      if (event.key === '?') {
        event.preventDefault();
        setHelpOpen(true);
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

    <header className="topbar">
      <div className="topbar-brand">
        <a className="brand" href={analysisId ? homeHref : '/'} onClick={event => {if (!analysisId) return;event.preventDefault();navigate(analysisId,'',filters);}}>
          <span className="brand-mark"><TraceIcon icon={Waypoints} size={20} /></span>
          <span className="brand-name">TraceBack<small>智溯</small></span>
        </a>
      </div>
      <form className="topbar-search" role="search" onSubmit={event => {event.preventDefault();navigate(input.trim(),'',DEFAULT_FILTERS);}}>
        <label className="sr-only" htmlFor="analysis-input">分析 ID</label>
        <div className="tb-search-input">
          <TraceIcon icon={Search} size={14}/>
          <input aria-describedby="analysis-hint" id="analysis-input" value={input} placeholder="粘贴 ana_… 分析 ID 打开快照" onChange={event => setInput(event.target.value)} required pattern="ana_[a-f0-9]{64}" />
          <span aria-hidden className="topbar-search-hint">/</span>
        </div>
        <span className="sr-only" id="analysis-hint">ana_ 前缀加 64 位十六进制</span>
        <button aria-label="从剪贴板粘贴分析 ID" className="topbar-paste" disabled={!navigator.clipboard?.readText} onClick={pasteAnalysis} type="button"><TraceIcon icon={ClipboardPaste} size={14}/></button>
        <Button size="sm" type="submit" variant={analysisId ? 'secondary' : 'default'}>打开分析</Button>
      </form>
      <div className="topbar-actions">
        <button aria-label="查看快捷键" className="icon-button" onClick={() => setHelpOpen(true)} type="button"><TraceIcon icon={CircleHelp} size={17}/></button>
        <button aria-expanded={menuOpen} aria-label="打开导航菜单" className="icon-button mobile-menu-button" onClick={openMenu} ref={menuButtonRef} type="button"><TraceIcon icon={Menu} size={18}/></button>
      </div>
    </header>

    <aside aria-label="侧边导航" className="sidebar">
      <div className="sidebar-scope">
        <p className="sidebar-label">分析范围</p>
        {analysisId
          ? <><CopyId className="sidebar-scope-row" label="当前分析 ID" value={analysisId}/><p className="sidebar-scope-meta">冻结快照 · 离线可复核</p></>
          : <><span className="sidebar-scope-empty">尚未打开分析</span><p className="sidebar-scope-meta">从顶栏粘贴分析 ID</p></>}
      </div>
      <nav aria-label="调查流程">
        <p className="nav-label">工作区</p>
        <button aria-current={activeList ? 'page' : undefined} className={'nav-item ' + (activeList ? 'active' : '')} onClick={() => analysisId && navigate(analysisId)} type="button"><TraceIcon icon={LayoutDashboard} size={15}/>分析工作台</button>
        <button aria-current={incidentId ? 'page' : undefined} className={'nav-item ' + (incidentId ? 'active' : '')} onClick={() => analysisId && navigate(analysisId,'',{...filters,page:1,kind:'has_chain'})} title="查看有向攻击链事件" type="button"><TraceIcon icon={GitBranch} size={15}/>安全事件 / 证据研判</button>
      </nav>
      <div className="sidebar-spacer"/>
      <div className="sidebar-foot">
        <button className="sidebar-help" onClick={() => setHelpOpen(true)} type="button">键盘快捷键 <Kbd>?</Kbd></button>
        <p className="sidebar-note">离线快照 · 可核验证据<br/>原始告警 ≠ 已确认攻击</p>
      </div>

      <dialog aria-label="调查流程导航" className="mobile-nav" onCancel={closeMenu} onClose={() => setMenuOpen(false)} ref={menuRef}>
        <div className="mobile-nav-head"><strong>工作区</strong><button aria-label="关闭导航菜单" className="icon-button" onClick={closeMenu} type="button"><TraceIcon icon={X} size={18}/></button></div>
        {analysisId && <CopyId className="mobile-nav-scope" label="当前分析 ID" value={analysisId}/>}
        <button aria-current={activeList ? 'page' : undefined} className={'nav-item ' + (activeList ? 'active' : '')} onClick={() => {closeMenu();analysisId && navigate(analysisId);}} type="button"><TraceIcon icon={LayoutDashboard} size={16}/>分析工作台</button>
        <button aria-current={incidentId ? 'page' : undefined} className={'nav-item ' + (incidentId ? 'active' : '')} onClick={() => {closeMenu();analysisId && navigate(analysisId,'',{...filters,page:1,kind:'has_chain'});}} type="button"><TraceIcon icon={GitBranch} size={16}/>安全事件 / 证据研判</button>
        <button className="nav-item" onClick={() => {closeMenu();setHelpOpen(true);}} type="button"><TraceIcon icon={CircleHelp} size={16}/>键盘快捷键</button>
        <p className="mobile-nav-foot">离线快照 · 可核验证据<br/>原始告警 ≠ 已确认攻击</p>
      </dialog>
    </aside>

    <div className="sheet">
      <main aria-label="主要内容" id="main-content" ref={mainRef} tabIndex={-1}>
        {!online && <div className="offline-banner" role="status">当前处于离线状态：已加载的数据仍可查看；重新请求或生成 AI 研判会失败。</div>}
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
    <Dialog onOpenChange={setHelpOpen} open={helpOpen}>
      <DialogPopup aria-label="键盘快捷键" className="max-w-lg">
        <DialogHeader><DialogTitle className="text-xl font-semibold">键盘快捷键</DialogTitle><DialogDescription>输入框内不触发；对话框内按 Esc 先关闭对话框。</DialogDescription></DialogHeader>
        <dl className="shortcut-list">
          <div><dt><Kbd>/</Kbd></dt><dd>聚焦搜索框（列表页）或分析 ID 输入框</dd></div>
          <div><dt><Kbd>?</Kbd></dt><dd>打开本快捷键帮助</dd></div>
          <div><dt><Kbd>Esc</Kbd></dt><dd>关闭证据抽屉 / 清空搜索 / 退出输入框</dd></div>
          <div><dt><Kbd>j</Kbd> <Kbd>k</Kbd></dt><dd>在事件列表行之间上下移动焦点</dd></div>
          <div><dt><Kbd>Enter</Kbd> <Kbd>Space</Kbd></dt><dd>打开当前聚焦的事件行</dd></div>
          <div><dt><Kbd>←→↑↓</Kbd> <Kbd>Home</Kbd> <Kbd>End</Kbd></dt><dd>攻击链节点/边之间移动选择</dd></div>
        </dl>
        <DialogFooter><Button onClick={() => setHelpOpen(false)} type="button" variant="outline">关闭</Button></DialogFooter>
      </DialogPopup>
    </Dialog>
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
        <Button onClick={() => {this.setState({failed:false});window.scrollTo(0,0);}} type="button" variant="outline">重试当前页面</Button>
        <Button onClick={() => location.reload()} type="button" variant="outline">重新加载</Button>
      </div>
    </div>;
  }
}

export default function App() {return <Workspace/>;}
