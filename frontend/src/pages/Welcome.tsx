import {useEffect, useState} from 'react';
import {api} from '../api/client';
import {loadRecentAnalyses} from '../lib/recent';
import {CopyId} from '../components/ui/copy-id';

interface RecentItem {analysisId: string; openedAt?: string; createdAt?: string; incidentCount?: number; status?: string}

/** First run: one noun title, the recent analyses as a working list, no hero. */
export default function Welcome({onOpen}: {onOpen: (analysisId: string) => void}) {
  const [remote,setRemote] = useState<RecentItem[] | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    api.analyses(controller.signal).then(result => {if (!controller.signal.aborted) setRemote(result.items.map(item => ({analysisId:item.analysis_id,createdAt:item.created_at,incidentCount:item.incident_count,status:item.status})));})
      .catch(() => {if (!controller.signal.aborted) setRemote([]);});
    return () => controller.abort();
  },[]);
  const local = loadRecentAnalyses().map(item => ({analysisId:item.analysisId,openedAt:item.openedAt}));
  const recent: RecentItem[] = remote?.length ? remote.slice(0, 6) : local;
  return <div className="welcome">
    <h1 data-page-title tabIndex={-1}>从碎片告警，回到可核验的调查。</h1>
    <p className="welcome-lede">粘贴分析 ID 打开冻结快照，或从最近的分析继续。所有结论都能回到设备告警、攻击链节点和字段指针。</p>
    <div className="welcome-grid">
      <section aria-label="最近打开的分析" className="recent-analyses">
        <h2>最近打开的分析</h2>
        {recent.length
          ? <ul>{recent.map(item => <li key={item.analysisId}><button onClick={() => onOpen(item.analysisId)} type="button"><CopyId copy={false} label="最近分析 ID" value={item.analysisId}/><span>{item.incidentCount !== undefined ? `${item.incidentCount.toLocaleString()} 事件` : ''}{item.openedAt ? ` · ${new Date(item.openedAt).toLocaleString('zh-CN')}` : ''}{item.createdAt ? ` · ${new Date(item.createdAt).toLocaleString('zh-CN')}` : ''}</span></button></li>)}</ul>
          : remote === null ? <p className="muted">正在读取分析列表…</p> : <p className="muted">本机还没有记录。打开一次分析后会出现在这里。</p>}
      </section>
      <aside aria-label="工作台说明" className="welcome-aside">
        <h2>这份工作台回答什么</h2>
        <dl className="facts">
          <div className="fact"><dt>关联判定</dt><dd>为什么只有 0 条或 1 条正式关联边，是严格证据准入还是漏召回。</dd></div>
          <div className="fact"><dt>节点构造</dt><dd>每个攻击步骤由哪些告警、实体和显式关系构成，置信分从哪来。</dd></div>
          <div className="fact"><dt>证据回溯</dt><dd>AI 结论只引用已验证 claim；被拒绝内容隔离在诊断里。</dd></div>
        </dl>
        <h2>离线快照</h2>
        <p>先在本地构建前端，再运行 <code>python scripts/demo.py --analysis-id &lt;ID&gt;</code> 打开同一份真实快照；不做实时告警流。</p>
      </aside>
    </div>
    <div className="welcome-facts">
      <div><h3>离线快照</h3><p>只读冻结分析；不打开实时告警流，也不回写后端快照。</p></div>
      <div><h3>证据可回溯</h3><p>每个结论都能回到设备告警、实体、节点/边与字段指针。</p></div>
      <div><h3>AI 只解释</h3><p>已验证 claim 才进入正式报告；被拒绝内容隔离在诊断里。</p></div>
      <div><h3>非目标</h3><p>不做自动处置、不做实时监控；原始告警不等于已确认攻击。</p></div>
    </div>
  </div>;
}
