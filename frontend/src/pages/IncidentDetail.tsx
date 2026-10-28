import {severityLabel, statusLabel, sourceLabel, fieldLabel, entityLabel, incidentKindLabel} from '../lib/displayLabels';
import {ArrowLeft} from 'lucide-react';
import {useEffect, useState} from 'react';
import {api} from '../api/client';
import {useResource} from '../api/hooks';
import {ChainGraph, type Selection} from '../components/attack-chain/ChainGraph';
import {EdgeDetailPanel, NodeDetail} from '../components/attack-chain/ObjectDetail';
import {AIReport} from '../components/ai-analysis/AIReport';
import {DetailNav} from '../components/DetailNav';
import {Notice, Section, StableId, Time} from '../components/common';
import {ErrorState} from '../components/ui/error-state';
import {TextSkeleton} from '../components/ui/skeleton';
import {TraceIcon} from '../components/ui/trace-icon';
import type {EvidenceSelection, Json} from '../types/domain';
import {Timeline} from './Timeline';

const CHAIN_STATUS_LABEL: Record<string, string> = {complete: '攻击链完整', partial: '部分攻击链', unknown: '攻击链状态未知'};

function formatObservationValue(value: Json): string {
  if (value === null || value === undefined) return '未提供';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) return value.map(item => typeof item === 'string' ? item : JSON.stringify(item)).join('、');
  const record = value as Record<string, Json>;
  const parts = ['name', 'host', 'ip', 'account', 'command', 'path', 'pid', 'start_time'].filter(key => record[key] !== undefined && record[key] !== null).map(key => `${key === 'name' ? '' : key + ' '}${String(record[key])}`.trim());
  return parts.length ? parts.join(' · ') : JSON.stringify(value);
}

export default function IncidentDetail({analysisId, incidentId, initialNodeId = '', initialEdgeId = '', timelinePage = 1, onEvidence, onBack, onGenerated, onSelectionChange, onTimelinePage}: {analysisId: string; incidentId: string; initialNodeId?: string; initialEdgeId?: string; timelinePage?: number; onEvidence: (e: EvidenceSelection) => void; onBack: () => void; onGenerated: () => void; onSelectionChange?: (selection: Selection) => void; onTimelinePage?: (page: number) => void}) {
  const resource = useResource(async signal => {
    const [detailResult, chainResult, observationsResult] = await Promise.allSettled([api.incident(analysisId,incidentId,signal),api.chain(analysisId,incidentId,signal),api.observations(analysisId,incidentId,signal)]);
    if (detailResult.status === 'rejected') throw new Error('incident_snapshot_error');
    if (chainResult.status === 'rejected') throw new Error('chain_snapshot_error');
    if (observationsResult.status === 'rejected') throw new Error('observations_snapshot_error');
    const [detail, chain, observations] = [detailResult.value, chainResult.value, observationsResult.value];
    if ([detail.analysis_id,chain.analysis_id,observations.analysis_id].some(a => a !== analysisId) || detail.incident.incident_id !== incidentId || chain.chain.incident_id !== incidentId) throw new Error('snapshot_scope_mismatch');
    return {detail, chain: chain.chain, observations};
  }, [analysisId,incidentId], {keepPrevious:true});
  const [selection, setSelection] = useState<Selection>(() => initialNodeId ? {kind:'node',id:initialNodeId} : initialEdgeId ? {kind:'edge',id:initialEdgeId} : null);
  const d = resource.data, node = d?.chain.nodes.find(n => selection?.kind === 'node' && n.node_id === selection.id), edge = d?.chain.edges.find(e => selection?.kind === 'edge' && e.edge_id === selection.id);
  useEffect(() => {
    const next: Selection = initialNodeId ? {kind:'node',id:initialNodeId} : initialEdgeId ? {kind:'edge',id:initialEdgeId} : null;
    setSelection(current => current?.kind === next?.kind && current?.id === next?.id ? current : next);
  },[initialNodeId,initialEdgeId]);
  const title = d?.detail.incident.summary ?? (d ? incidentKindLabel(d.observations.representative_member_count) : '安全事件');
  useEffect(() => {
    if (!selection) return;
    const panel = document.getElementById('object-detail');
    if (!panel) return;
    panel.focus({preventScroll:true});
    panel.scrollIntoView({behavior:'smooth', block:'nearest'});
  },[selection]);
  useEffect(() => {if (d) document.title = title + ' · TraceBack';},[d,title]);
  function select(kind: 'node' | 'edge', id: string) {setSelection({kind,id});onSelectionChange?.({kind,id});}
  const chainStatus = d?.detail.chain_status ?? '';
  const memberLine = d ? `${d.observations.representative_member_count ?? '未提供'} 去重代表 · ${d.observations.expanded_member_count ?? d.detail.incident.alert_ids.length} 展开告警 · ${d.chain.nodes.length} 节点 · ${d.chain.edges.length} 边` : '';
  return <>
    <nav aria-label="面包屑" className="detail-breadcrumbs"><button className="back-button inline-flex items-center gap-1.5" onClick={onBack} type="button"><TraceIcon icon={ArrowLeft} size={15}/>返回调查队列</button><span aria-hidden>/</span><span aria-current="page">安全事件</span></nav>
    {resource.loading && !d && <div aria-label="正在打开安全事件" className="space-y-4" role="status"><TextSkeleton lines={2}/><div className="panel"><TextSkeleton lines={6}/></div></div>}
    {resource.loading && !d && <Notice kind="loading">正在打开安全事件…</Notice>}
    {resource.error && <ErrorState error={resource.error} onRetry={resource.reload} scope="安全事件详情"/>}
    {d && <>
      <div className="analysis-heading detail-heading">
        <div className="min-w-0"><span className="eyebrow">安全事件 / 调查上下文</span><h1 data-page-title tabIndex={-1}>{title}</h1>
          <div className="detail-badges"><span className={'severity severity-' + d.detail.incident.severity}>{severityLabel(d.detail.incident.severity)}</span><span className="badge">{incidentKindLabel(d.observations.representative_member_count)}</span><span className="badge">{statusLabel(d.detail.incident.status)}</span><span className={'badge chain-' + chainStatus}>{CHAIN_STATUS_LABEL[chainStatus] ?? statusLabel(chainStatus)}</span></div>
          <p className="detail-ids"><StableId label="安全事件 ID" value={incidentId}/> · 分析 <StableId label="分析 ID" value={analysisId}/></p>
        </div>
        <div className="analysis-heading-actions"><a className="button-link" href="#ai-report">跳到 AI 研判</a></div>
      </div>
      <div className="detail-nav-sticky"><DetailNav/></div>
      <Section id="incident-overview" title="安全事件概况"><div className="overview-grid"><div><dl className="facts"><dt>观察区间</dt><dd><Time value={d.detail.incident.start_time}/><br/><Time value={d.detail.incident.end_time}/></dd><dt>成员</dt><dd>{memberLine}</dd><dt>来源</dt><dd>{d.observations.sources.map(sourceLabel).join(' · ')}</dd><dt>工作流状态</dt><dd>{statusLabel(d.detail.incident.status)} · {CHAIN_STATUS_LABEL[chainStatus] ?? statusLabel(chainStatus)}</dd></dl></div><div className="observations">{d.observations.fields.length ? d.observations.fields.map((f,index) => <div className="entity-row" key={index}><b>{fieldLabel(f.field)}</b><span title={typeof f.value === 'string' ? f.value : JSON.stringify(f.value)}>{formatObservationValue(f.value)}</span><button onClick={() => onEvidence({title:'观测字段证据',objectId:incidentId,alertIds:f.alert_ids,pointers:f.pointers})} type="button">证据</button></div>) : <Notice>该事件未提供可展示的网络或主机字段。</Notice>}</div></div>
        <details><summary>全部关键实体（{d.detail.entities.length}）</summary>{d.detail.entities.map(e => <p key={e.entity_id}><b>{entityLabel(e.type)}</b> {e.display_value ?? e.value} <StableId label="实体 ID" value={e.entity_id}/></p>)}</details></Section>
      <div id="attack-chain"><Section title="攻击链 · 已观测步骤与传播" hint="算法负责关联与重构"><ChainGraph chain={d.chain} entities={d.detail.entities} selection={selection} onSelect={value => value && select(value.kind, value.id)}/><p aria-live="polite" className="sr-only" role="status">{selection ? `已选择${selection.kind === 'node' ? '节点' : '边'} ${selection.id}` : ''}</p><div className="object-detail-focus" id="object-detail" tabIndex={-1}>{node ? <NodeDetail node={node} entities={d.detail.entities} onEvidence={onEvidence}/> : edge ? <EdgeDetailPanel key={edge.edge_id} analysisId={analysisId} edge={edge} onEvidence={onEvidence} onNode={id => select('node',id)}/> : <Notice>点击节点查看构造依据和告警；点击有向边查看方向、评分与支撑证据。</Notice>}</div></Section></div>
      <Section id="incident-evidence" title="证据 · 告警与标准化引用" hint="证据负责回溯"><p>所有成员来自当前分析。原始告警默认折叠，按需读取。</p><button className="primary" onClick={() => onEvidence({title:'安全事件成员告警',objectId:incidentId,alertIds:d.detail.incident.alert_ids})} type="button">查看全部成员证据 · {d.detail.incident.alert_ids.length}</button></Section>
      <Timeline analysisId={analysisId} incidentId={incidentId} initialPage={timelinePage} onPageChange={onTimelinePage} onEvidence={onEvidence} onNode={id => select('node',id)}/>
      <AIReport analysisId={analysisId} incidentId={incidentId} chain={d.chain} onEvidence={onEvidence} onSelect={select} onGenerated={onGenerated}/>
    </>}
  </>;
}
