import {categoryLabel, severityLabel, statusLabel, sourceLabel, analysisMetrics} from '../lib/displayLabels';
import {ScoreDiagnostic} from '../components/ScoreDiagnostic';
import {api} from '../api/client';
import {useResource} from '../api/hooks';
import {Notice, Section, StableId, Time} from '../components/common';
import {EmptyState} from '../components/ui/empty-state';
import {ErrorState} from '../components/ui/error-state';
import {Skeleton, TextSkeleton} from '../components/ui/skeleton';

const DISTRIBUTIONS = [
  {key: 'source_type', title: '告警来源', label: sourceLabel},
  {key: 'severity', title: '设备观测等级', label: severityLabel},
  {key: 'category', title: '已观测类别', label: categoryLabel},
] as const;

function Distribution({analysisId, title, items, label, total}: {analysisId: string; title: string; items: {value: string; count: number}[]; label: (v: string) => string; total: number}) {
  const max = Math.max(total, 1);
  return <Section title={title}>
    {items.length ? items.map(item => {
      const percent = Math.round((item.count / max) * 1000) / 10;
      return <div className="distribution" key={item.value}>
        <span>{label(item.value)}</span>
        <b>{item.count.toLocaleString()}</b>
        <div aria-label={`${label(item.value)}：${item.count.toLocaleString()} 条，占 ${percent}%`} aria-valuemax={max} aria-valuemin={0} aria-valuenow={item.count} className="distribution-bar" role="meter"><span style={{width: `${Math.max(percent, 0.5)}%`}} /></div>
        <small className="muted distribution-percent">{percent}%</small>
      </div>;
    }) : <EmptyState description={`该分析快照没有可展示的${title}。`} title="未提供分布数据。" />}
    <p className="muted distribution-hint">按标准化告警计数 · 分析 {analysisId.slice(0, 12)}…</p>
  </Section>;
}

export default function Dashboard({analysisId}: {analysisId: string}) {
  const resource = useResource(signal => api.overview(analysisId, signal), [analysisId], {keepPrevious:true});
  const d = resource.data;
  const totalAlerts = d?.counts.canonical_alert_count ?? 0;
  return <>
    {resource.loading && !d && <div aria-label="正在加载分析" className="space-y-4" role="status"><Skeleton className="h-7 w-64"/><TextSkeleton lines={2}/><div className="metric-grid">{Array.from({length:8}).map((_,i) => <Skeleton className="h-24 rounded-lg" key={i}/>)}</div></div>}
    {resource.loading && !d && <Notice kind="loading">正在读取分析…</Notice>}
    {resource.error ? <ErrorState error={resource.error} onRetry={resource.reload} scope="分析快照"/> : null}
    {d && <>
      <div className="analysis-heading">
        <div><span className="eyebrow">冻结分析快照</span><h1 data-page-title tabIndex={-1}>安全事件工作台</h1><p><StableId label="分析 ID" value={d.analysis_id}/> · <Time value={d.created_at}/></p></div>
        <div className="analysis-heading-actions"><span className={'badge ' + (d.is_complete ? 'verified' : 'warning')}>{statusLabel(d.status)}</span><a className="button-link primary-link" href="#incident-list">查看全部事件</a></div>
      </div>
      {!d.is_complete && <Notice kind="info">该分析尚不完整：{d.incomplete_reason ?? d.status}</Notice>}
      <div aria-label="关键指标" className="metric-grid" role="group">{analysisMetrics.map(([key, title]) => <article className="metric" data-metric={key} key={key}><span>{title}</span><strong>{(d.counts[key] ?? 0).toLocaleString()}</strong></article>)}</div>
      <Section title="去重诊断" hint="独立维度 · 不改变攻击步骤判定"><p>含去重展开的事件：<b>{(d.counts.incidents_with_dedupe_expansion_count ?? 0).toLocaleString()}</b></p><p className="muted">事件分类按去重代表数量统计；重复告警展开属于独立维度，不代表不同攻击步骤已关联。</p></Section>
      <ScoreDiagnostic data={d.score_diagnostics}/>
      <div className="distribution-grid">{DISTRIBUTIONS.map(({key, title, label}) => <Distribution analysisId={analysisId} items={d.distributions[key]} key={key} label={label} title={title} total={totalAlerts} />)}</div>
      <details className="diagnostics"><summary>分析诊断 / 可复核配置</summary><dl className="facts"><dt>算法版本</dt><dd>{d.algorithm_version}</dd><dt>配置摘要</dt><dd><code>{d.config_hash}</code></dd><dt>快照清单</dt><dd><code>{d.manifest_ref}</code></dd><dt>诊断引用</dt><dd><code>{d.diagnostics_ref}</code></dd></dl>{d.errors.concat(d.warnings).map(e => <p key={e}>{e}</p>)}</details>
    </>}
  </>;
}
