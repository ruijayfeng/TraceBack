import {sourceLabel, kindLabel} from '../lib/displayLabels';
import {useState} from 'react';
import {api} from '../api/client';
import {useResource} from '../api/hooks';
import type {EvidenceSelection, TimelineItem} from '../types/domain';
import {Notice, Pager, Section, StableId, Time} from '../components/common';
export function Timeline({analysisId, incidentId, onEvidence, onNode}: {analysisId: string; incidentId: string; onEvidence: (e: EvidenceSelection) => void; onNode: (id: string) => void}) {
  const [page, setPage] = useState(1), [zoom, setZoom] = useState(1);
  const resource = useResource(signal => api.timeline(analysisId, incidentId, page, signal), [analysisId, incidentId, page]);
  const items = resource.data?.items ?? [];
  const lanes = [...new Set(items.map(i => sourceLabel(i.source_type) + ' / ' + (i.sensor ?? '未提供设备')))];
  const start = items.length ? Math.min(...items.map(i => Date.parse(i.event_time))) : 0;
  const end = items.length ? Math.max(...items.map(i => Date.parse(i.end_time))) : 0;
  const choose = (i: TimelineItem) => i.kind === 'node' ? onNode(i.node_id!) : onEvidence({title:'时间线告警', objectId:i.id, alertIds:i.alert_ids});
  return <Section title="设备观测时间线" hint="时间排列不表示因果"><div className="graph-toolbar"><span className="muted">当前页 · UTC · 完整微秒时间保留在下表</span><label>缩放<input aria-label="时间线缩放" type="range" min="1" max="4" step=".5" value={zoom} onChange={e => setZoom(Number(e.target.value))}/></label></div>
    {resource.loading && <Notice kind="loading">正在读取时间线…</Notice>}{resource.error && <Notice kind="error">时间线无法读取：{resource.error}</Notice>}
    {resource.data && (items.length ? <><div className="timeline-scroll"><div className="timeline" style={{minWidth: 650*zoom}}>{lanes.map(lane => <div className="timeline-lane" key={lane}><b>{lane}</b><div className="timeline-track">{items.filter(i => sourceLabel(i.source_type) + ' / ' + (i.sensor ?? '未提供设备') === lane).map(i => <button key={i.id} className={i.kind === 'node' ? 'timeline-node' : 'timeline-alert'} style={{left: `${3 + 90*(Date.parse(i.event_time)-start)/Math.max(1,end-start)}%`}} title={`${kindLabel(i.kind)} ${i.event_time} ${i.id}`} aria-label={`时间线 ${kindLabel(i.kind)} ${i.id}`} onClick={() => choose(i)}>{i.kind === 'node' ? '□' : '●'}</button>)}</div></div>)}</div></div><div className="table-scroll"><table><thead><tr><th>时间 / UTC</th><th>来源 / 设备</th><th>已有对象</th><th>引用</th></tr></thead><tbody>{items.map(i => <tr key={`${i.id}/${sourceLabel(i.source_type)}/${i.sensor}`}><td><Time value={i.event_time}/>{i.end_time !== i.event_time && <><br/><Time value={i.end_time}/></>}</td><td>{sourceLabel(i.source_type)} · {i.sensor ?? '未提供'}</td><td>{kindLabel(i.kind)}</td><td><button className="text-button" onClick={() => choose(i)}><StableId value={i.id}/></button></td></tr>)}</tbody></table></div></> : <Notice>当前页没有时间线对象。</Notice>)}
    {resource.data && <Pager page={page} total={resource.data.total} onChange={setPage}/>}</Section>;
}
