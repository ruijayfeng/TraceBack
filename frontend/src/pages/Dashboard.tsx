import {Fragment} from 'react';
import {categoryLabel, severityLabel, statusLabel, sourceLabel, analysisMetrics} from '../lib/displayLabels';
import {ScoreDiagnostic} from '../components/ScoreDiagnostic';
import {api} from '../api/client';
import {useResource} from '../api/hooks';
import {useMediaQuery} from '../lib/useMediaQuery';
import {Notice, PageHead, StableId, Time} from '../components/common';
import {Button} from '../components/ui/button';
import {Card} from '../components/ui/card';
import {ErrorState} from '../components/ui/error-state';
import {Skeleton, TextSkeleton} from '../components/ui/skeleton';
import {TraceIcon} from '../components/ui/trace-icon';
import {ArrowRight, ChevronRight} from 'lucide-react';

const DISTRIBUTIONS = [
  {key: 'source_type', title: '告警来源', label: sourceLabel},
  {key: 'severity', title: '设备观测等级', label: severityLabel},
  {key: 'category', title: '已观测类别', label: categoryLabel},
] as const;

function DistributionGroup({title, items, label, total}: {title: string; items: {value: string; count: number}[]; label: (v: string) => string; total: number}) {
  const max = Math.max(total, 1);
  return <div className="dist-group">
    <h3>{title}</h3>
    {items.length ? items.map(item => {
      const percent = Math.round((item.count / max) * 1000) / 10;
      return <div className="dist-row" key={item.value}>
        <span className="lbl">{label(item.value)}</span>
        <span className="val">{item.count.toLocaleString()}<small>{percent}%</small></span>
        <div aria-label={`${label(item.value)}：${item.count.toLocaleString()} 条，占 ${percent}%`} aria-valuemax={max} aria-valuemin={0} aria-valuenow={item.count} className="dist-bar" role="meter"><span style={{width: `${Math.max(percent, 0.5)}%`}} /></div>
      </div>;
    }) : <p className="muted-text" style={{fontSize: 12, margin: 0}}>未提供</p>}
  </div>;
}

export default function Dashboard({analysisId}: {analysisId: string}) {
  const resource = useResource(signal => api.overview(analysisId, signal), [analysisId], {keepPrevious:true});
  const compact = useMediaQuery('(max-width: 1100px)');
  const d = resource.data;
  const totalAlerts = d?.counts.canonical_alert_count ?? 0;
  const scoreAvailable = d?.score_diagnostics?.status === 'available';
  const configFacts = d && <>
    <dl className="facts">
      <div className="fact"><dt>算法版本</dt><dd>{d.algorithm_version}</dd></div>
      <div className="fact"><dt>配置摘要</dt><dd><code>{d.config_hash}</code></dd></div>
      <div className="fact"><dt>快照清单</dt><dd><code>{d.manifest_ref}</code></dd></div>
      <div className="fact"><dt>诊断引用</dt><dd><code>{d.diagnostics_ref}</code></dd></div>
    </dl>
    {d.errors.concat(d.warnings).map(e => <p className="muted-text" key={e} style={{fontSize: 12}}>{e}</p>)}
  </>;
  const diagnostics = d && <>
    <div className="dash-grid">
      <Card className="dash-card">
        <div className="card-head"><h2 className="card-title">去重诊断</h2><span className="card-hint">独立维度 · 不改变攻击步骤判定</span></div>
        <p className="dash-value"><strong>{(d.counts.incidents_with_dedupe_expansion_count ?? 0).toLocaleString()}</strong> 含去重展开的事件</p>
        <p className="dash-note">事件分类按去重代表数量统计；重复告警展开属于独立维度，不代表不同攻击步骤已关联。</p>
      </Card>
      <Card className="dash-card">
        <div className="card-head"><h2 className="card-title">分布</h2><span className="card-hint">按标准化告警计数</span></div>
        <div className="dist-grid">{DISTRIBUTIONS.map(({key, title, label}) => <DistributionGroup items={d.distributions[key]} key={key} label={label} title={title} total={totalAlerts}/>)}</div>
      </Card>
    </div>
    {scoreAvailable
      ? <><ScoreDiagnostic data={d.score_diagnostics}/><details className="subtle-details" style={{marginBottom: 8}}><summary>分析诊断与复核配置</summary>{configFacts}</details></>
      : <details className="subtle-details" style={{marginBottom: 8}}><summary>分析诊断与复核配置</summary><ScoreDiagnostic data={d.score_diagnostics}/>{configFacts}</details>}
  </>;
  return <>
    {resource.loading && !d && <div aria-label="正在加载分析" role="status">
      <div className="page-head"><div className="w-full space-y-3"><Skeleton className="h-7 w-56"/><TextSkeleton lines={1}/></div></div>
      <Card className="trace-card"><div className="trace-band">{[0,1,2,3,4,5,6,7].map(i => <div className="trace-cell" key={i}><Skeleton className="h-3 w-16"/><Skeleton className="mt-2 h-7 w-10"/></div>)}</div></Card>
    </div>}
    {resource.loading && !d && <Notice kind="loading">正在读取分析…</Notice>}
    {resource.error ? <ErrorState error={resource.error} onRetry={resource.reload} scope="分析快照"/> : null}
    {d && <>
      <PageHead
        actions={<>
          <span className={'pill ' + (d.is_complete ? 'pill-success' : 'pill-warning')}>{statusLabel(d.status)}</span>
          <Button render={<a href="#incident-list" />} size="sm">查看全部事件<TraceIcon icon={ArrowRight} size={14}/></Button>
        </>}
        className="workbench-head"
        meta={<><StableId label="分析 ID" value={d.analysis_id}/><span aria-hidden>·</span><Time value={d.created_at}/><span aria-hidden>·</span><span>冻结分析快照</span></>}
        title="安全事件工作台"
      />
      {!d.is_complete && <Notice kind="info">该分析尚不完整：{d.incomplete_reason ?? d.status}</Notice>}
      <Card className="trace-card">
        <div aria-label="关键指标" className="trace-band" role="group">
          {analysisMetrics.map(([key, title], index) => <Fragment key={key}>
            {index > 0 && index < 4 && <span aria-hidden className="trace-sep"><TraceIcon icon={ChevronRight} size={13}/></span>}
            <div className={'trace-cell' + (index >= 4 ? ' is-counter' : '')}><article className="metric" data-metric={key}><span>{title}</span><strong>{(d.counts[key] ?? 0).toLocaleString()}</strong></article></div>
          </Fragment>)}
        </div>
      </Card>
      {compact
        ? <details className="diag-disclosure"><summary>分析诊断 · 去重 / 分布 / 评分</summary>{diagnostics}</details>
        : diagnostics}
    </>}
  </>;
}
