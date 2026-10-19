import {severityLabel, statusLabel, sourceLabel, fieldLabel, entityLabel, incidentKindLabel} from '../lib/displayLabels';
import {useState} from 'react';
import {api} from '../api/client';
import {useResource} from '../api/hooks';
import {ChainGraph, type Selection} from '../components/attack-chain/ChainGraph';
import {EdgeDetailPanel, NodeDetail} from '../components/attack-chain/ObjectDetail';
import {AIReport} from '../components/ai-analysis/AIReport';
import {Notice, Section, StableId, Time} from '../components/common';
import type {EvidenceSelection} from '../types/domain';
import {Timeline} from './Timeline';
export default function IncidentDetail({analysisId, incidentId, onEvidence, onBack, onGenerated}: {analysisId: string; incidentId: string; onEvidence: (e: EvidenceSelection) => void; onBack: () => void; onGenerated: () => void}) {
  const resource = useResource(async signal => {
    const [detail, chain, observations] = await Promise.all([api.incident(analysisId,incidentId,signal),api.chain(analysisId,incidentId,signal),api.observations(analysisId,incidentId,signal)]);
    if ([detail.analysis_id,chain.analysis_id,observations.analysis_id].some(a => a !== analysisId) || detail.incident.incident_id !== incidentId || chain.chain.incident_id !== incidentId) throw new Error('snapshot_scope_mismatch');
    return {detail, chain: chain.chain, observations};
  }, [analysisId,incidentId]);
  const [selection, setSelection] = useState<Selection>(null);
  const d = resource.data, node = d?.chain.nodes.find(n => selection?.kind === 'node' && n.node_id === selection.id), edge = d?.chain.edges.find(e => selection?.kind === 'edge' && e.edge_id === selection.id);
  function select(kind: 'node' | 'edge', id: string) {setSelection({kind,id}); document.getElementById('attack-chain')?.scrollIntoView({behavior:'smooth', block:'start'});}
  return <><button className="back-button" onClick={onBack}>← 返回调查队列</button>{resource.loading && <Notice kind="loading">正在打开安全事件…</Notice>}{resource.error && <Notice kind="error">安全事件无法打开：{resource.error}</Notice>}{d && <>
    <div className="analysis-heading"><div><span className="eyebrow">安全事件 / 调查上下文</span><h1>{incidentKindLabel(d.observations.representative_member_count)}</h1><p><StableId value={incidentId}/> · 分析 <StableId value={analysisId}/></p></div><span className={'severity severity-' + d.detail.incident.severity}>{severityLabel(d.detail.incident.severity)}</span></div>
    <Section title="安全事件概况"><div className="overview-grid"><div><dl className="facts"><dt>观察区间</dt><dd><Time value={d.detail.incident.start_time}/><br/><Time value={d.detail.incident.end_time}/></dd><dt>成员</dt><dd>{d.observations.representative_member_count ?? '未提供'} 去重代表 · {d.detail.incident.alert_ids.length} 展开告警 · {d.chain.nodes.length} 节点 · {d.chain.edges.length} 边</dd><dt>来源</dt><dd>{d.observations.sources.map(sourceLabel).join(' · ')}</dd><dt>工作流状态</dt><dd>{statusLabel(d.detail.incident.status)}</dd></dl></div><div className="observations">{d.observations.fields.length ? d.observations.fields.map((f,index) => <div className="entity-row" key={index}><b>{fieldLabel(f.field)}</b><span>{typeof f.value === 'string' ? f.value : JSON.stringify(f.value)}</span><button onClick={() => onEvidence({title:'观测字段证据',objectId:incidentId,alertIds:f.alert_ids,pointers:f.pointers})}>证据</button></div>) : <Notice>该事件未提供可展示的网络或主机字段。</Notice>}</div></div>
      <details><summary>全部关键实体（{d.detail.entities.length}）</summary>{d.detail.entities.map(e => <p key={e.entity_id}><b>{entityLabel(e.type)}</b> {e.display_value ?? e.value} <StableId value={e.entity_id}/></p>)}</details></Section>
    <div id="attack-chain"><Section title="攻击链 · 已观测步骤与传播" hint="算法负责关联与重构"><ChainGraph chain={d.chain} entities={d.detail.entities} selection={selection} onSelect={setSelection}/>{node ? <NodeDetail node={node} entities={d.detail.entities} onEvidence={onEvidence}/> : edge ? <EdgeDetailPanel key={edge.edge_id} analysisId={analysisId} edge={edge} onEvidence={onEvidence} onNode={id => setSelection({kind:'node',id})}/> : <Notice>点击节点查看构造依据和告警；点击有向边查看方向、评分与支撑证据。</Notice>}</Section></div>
    <Section title="证据 · 告警与标准化引用" hint="证据负责回溯"><p>所有成员来自当前分析。原始告警默认折叠，按需读取。</p><button className="primary" onClick={() => onEvidence({title:'安全事件成员告警',objectId:incidentId,alertIds:d.detail.incident.alert_ids})}>查看全部成员证据 · {d.detail.incident.alert_ids.length}</button></Section>
    <Timeline analysisId={analysisId} incidentId={incidentId} onEvidence={onEvidence} onNode={id => select('node',id)}/>
    <AIReport analysisId={analysisId} incidentId={incidentId} chain={d.chain} onEvidence={onEvidence} onSelect={select} onGenerated={onGenerated}/>
  </>}</>;
}
