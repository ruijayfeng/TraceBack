import OverviewPage from './OverviewPage';
import {api} from '../../api/client';
import {useResource, type Resource} from '../../api/hooks';
import {Notice} from '../../components/common';
import AnalysisModule from '../AnalysisModule';
import type {StageCatalog} from '../../types/stageAnalysis';

// Loads the latest official analysis + read-only summary, then renders the
// 态势总览 landing page. Never falls back to legacy data when the official
// analysis is absent; it surfaces the empty state instead.
export default function OverviewContainer({onOpenStage, view = 'overview', analysisId = '', onNavigate, catalog}: {onOpenStage: (analysisId: string, chainId?: string) => void; view?: string; analysisId?: string; onNavigate: (view: string, query?: string) => void; catalog: Resource<StageCatalog>}) {
  const identity = analysisId || catalog.data?.default_analysis_id || '';
  const analysis = useResource(signal => identity ? api.stageAnalysis(identity, signal) : Promise.resolve(null), [identity]);
  const summary = useResource(signal => identity && view==='overview' ? api.stageSummary(identity, signal) : Promise.resolve(null), [identity,view==='overview']);

  if (catalog.loading) return <Notice kind="loading">正在识别最新正式分析结果…</Notice>;
  if (catalog.error) return <Notice kind="error">无法读取分析记录：{catalog.error}</Notice>;
  if (!identity) return <Notice>未找到最新正式分析结果。</Notice>;
  if (analysis.loading) return <Notice kind="loading">正在读取正式分析结果…</Notice>;
  if (analysis.error) return <Notice kind="error">分析无法打开：{analysis.error}</Notice>;
  if (!analysis.data) return <Notice>未找到最新正式分析结果。</Notice>;
  if(analysis.data.analysis_id !== identity) return <Notice kind="error">分析记录不匹配，请重新选择分析。</Notice>;

  if(view !== 'overview') return <AnalysisModule key={identity+view} view={view} data={analysis.data} onOpenChain={id=>onOpenStage(identity,id)}/>;
  if(summary.loading) return <Notice kind="loading">正在读取告警分布…</Notice>;
  if(summary.error) return <Notice kind="error">告警分布无法读取：{summary.error}</Notice>;
  if(!summary.data || summary.data.analysis_id !== identity || analysis.data.analysis_id !== identity) return <Notice kind="error">分析与汇总记录不匹配，请重新选择分析。</Notice>;
  return <OverviewPage
    analysisId={identity}
    data={analysis.data}
    summary={summary.data ?? {analysis_id: identity, summary: {counts: {input_count: 0, kept_count: 0, stage_count: 0, host_count: 0}, source_type: [], source_namespace: [], source_product: [], hosts: [], behavior: [], time_series: []}}}
    onOpenChain={chainId => onOpenStage(identity,chainId)}
    onNavigate={onNavigate}
  />;
}
