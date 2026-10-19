import {categoryLabel, severityLabel, statusLabel, sourceLabel, analysisMetrics} from '../lib/displayLabels';
import {ScoreDiagnostic} from '../components/ScoreDiagnostic';
import {api} from '../api/client';
import {useResource} from '../api/hooks';
import {Notice, Section, StableId, Time} from '../components/common';
export default function Dashboard({analysisId}: {analysisId: string}) {
  const resource = useResource(signal => api.overview(analysisId, signal), [analysisId]);
  const d = resource.data;
  return <>{resource.loading && <Notice kind="loading">正在读取分析…</Notice>}{resource.error && <Notice kind="error">分析无法打开：{resource.error}</Notice>}{d && <><div className="analysis-heading"><div><span className="eyebrow">冻结分析快照</span><h1>安全事件工作台</h1><p><StableId value={d.analysis_id}/> · <Time value={d.created_at}/></p></div><span className={'badge ' + (d.is_complete ? 'verified' : 'warning')}>{statusLabel(d.status)}</span></div>
    {!d.is_complete && <Notice kind="info">该分析尚不完整：{d.incomplete_reason ?? d.status}</Notice>}
    <div className="metric-grid">{analysisMetrics.map(([key, title]) => <article className="metric" key={key}><span>{title}</span><strong>{(d.counts[key] ?? 0).toLocaleString()}</strong></article>)}</div>
    <Section title="去重诊断"><p>含去重展开的事件：<b>{(d.counts.incidents_with_dedupe_expansion_count ?? 0).toLocaleString()}</b></p><p>事件分类按去重代表数量统计；重复告警展开属于独立维度，不代表不同攻击步骤已关联。</p></Section>
    <ScoreDiagnostic data={d.score_diagnostics}/>
    <div className="distribution-grid">{[['source_type','告警来源'],['severity','设备观测等级'],['category','已观测类别']].map(([key,title]) => <Section key={key} title={title}>{d.distributions[key].map(item => <div className="distribution" key={item.value}><span>{(key === 'source_type' ? sourceLabel : key === 'severity' ? severityLabel : categoryLabel)(item.value)}</span><b>{item.count.toLocaleString()}</b><meter min={0} max={d.counts.canonical_alert_count || 1} value={item.count}/></div>)}</Section>)}</div>
    <details className="diagnostics"><summary>分析诊断 / 可复核配置</summary><dl className="facts"><dt>算法版本</dt><dd>{d.algorithm_version}</dd><dt>配置摘要</dt><dd><code>{d.config_hash}</code></dd><dt>快照清单</dt><dd><code>{d.manifest_ref}</code></dd><dt>诊断引用</dt><dd><code>{d.diagnostics_ref}</code></dd></dl>{d.errors.concat(d.warnings).map(e => <p key={e}>{e}</p>)}</details></>}
  </>;
}
