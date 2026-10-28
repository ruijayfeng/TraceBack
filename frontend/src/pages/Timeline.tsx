import {sourceLabel, kindLabel} from '../lib/displayLabels';
import {useEffect, useState} from 'react';
import {api} from '../api/client';
import {useResource} from '../api/hooks';
import type {EvidenceSelection, TimelineItem} from '../types/domain';
import {EmptyState} from '../components/ui/empty-state';
import {ErrorState} from '../components/ui/error-state';
import {TextSkeleton} from '../components/ui/skeleton';
import {Notice, Pager, Section, StableId, Time} from '../components/common';

/** Data marks stay local SVG: they are evidence glyphs, not UI icons. */
function TimelineMarker({kind}: {kind: TimelineItem['kind']}) {
  return <svg aria-hidden className="timeline-marker" height="10" viewBox="0 0 10 10" width="10">{kind === 'node' ? <rect height="9" rx="1.5" width="9" x="0.5" y="0.5"/> : <circle cx="5" cy="5" r="4"/>}</svg>;
}

function utcTick(ms: number, spanMs: number): string {
  const date = new Date(ms);
  const pad = (value: number) => String(value).padStart(2, '0');
  if (spanMs >= 86_400_000) return `${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}`;
  if (spanMs < 10_000) return `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}.${String(date.getUTCMilliseconds()).padStart(3, '0')}`;
  return `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}`;
}

export function Timeline({analysisId, incidentId, initialPage = 1, onPageChange, onEvidence, onNode}: {analysisId: string; incidentId: string; initialPage?: number; onPageChange?: (page: number) => void; onEvidence: (e: EvidenceSelection) => void; onNode: (id: string) => void}) {
  const [page, setPage] = useState(initialPage), [zoom, setZoom] = useState(1);
  useEffect(() => {setPage(initialPage);},[initialPage]);
  function changePage(next: number) {setPage(next);onPageChange?.(next);}
  const resource = useResource(signal => api.timeline(analysisId, incidentId, page, 20, signal), [analysisId, incidentId, page], {keepPrevious:true});
  const [bounds, setBounds] = useState<{start: number; end: number} | null>(null);
  const items = resource.data?.items ?? [];
  const total = resource.data?.total ?? 0;

  // Full-incident extent (not just this page): first + last timeline item.
  useEffect(() => {
    if (!total) {setBounds(null);return;}
    let cancelled = false;
    const controller = new AbortController();
    Promise.all([api.timeline(analysisId, incidentId, 1, 1, controller.signal), api.timeline(analysisId, incidentId, total, 1, controller.signal)])
      .then(([first, last]) => {
        if (cancelled) return;
        const start = Math.min(...first.items.map(i => Date.parse(i.event_time)), ...last.items.map(i => Date.parse(i.event_time)));
        const end = Math.max(...first.items.map(i => Date.parse(i.end_time)), ...last.items.map(i => Date.parse(i.end_time)));
        setBounds(Number.isFinite(start) && Number.isFinite(end) && end > start ? {start, end} : null);
      })
      .catch(() => {if (!cancelled) setBounds(null);});
    return () => {cancelled = true;controller.abort();};
  }, [analysisId, incidentId, total]);

  const lanes = [...new Set(items.map(i => sourceLabel(i.source_type) + ' / ' + (i.sensor ?? '未提供设备')))];
  const pageStart = items.length ? Math.min(...items.map(i => Date.parse(i.event_time))) : 0;
  const pageEnd = items.length ? Math.max(...items.map(i => Date.parse(i.end_time))) : 0;
  const start = bounds?.start ?? pageStart;
  const end = bounds?.end ?? pageEnd;
  const span = Math.max(1, end - start);
  const position = (time: string) => Math.max(1, Math.min(99, ((Date.parse(time) - start) / span) * 100));
  const ticks = Array.from({length: 5}, (_, index) => start + (span * index) / 4);
  const choose = (i: TimelineItem) => i.kind === 'node' ? onNode(i.node_id!) : onEvidence({title:'时间线告警', objectId:i.id, alertIds:i.alert_ids});

  return <Section id="incident-timeline" title="设备观测时间线" hint="时间排列不表示因果">
    <div className="graph-toolbar"><span className="muted">{bounds ? '全事件范围' : '当前页范围'} · UTC · 完整微秒时间保留在下表</span><label>缩放<input aria-label="时间线缩放" max="4" min="1" onChange={e => setZoom(Number(e.target.value))} step=".5" type="range" value={zoom}/></label></div>
    {resource.loading && <TextSkeleton lines={3}/>}
    {resource.loading && <Notice kind="loading">正在读取时间线…</Notice>}
    {resource.error && <ErrorState error={resource.error} onRetry={resource.reload} scope="设备观测时间线"/>}
    {resource.data && (items.length ? <><div className="timeline-scroll"><div className="timeline-canvas" style={{width: `${100 * zoom}%`}}>
      <div aria-hidden className="timeline-ruler"><span className="timeline-lane-label"/><div className="timeline-ruler-track">{ticks.map((tick, index) => <span className="timeline-tick" key={index} style={{left: `${2 + (index / 4) * 96}%`, transform: index === 0 ? 'translateX(0)' : index === 4 ? 'translateX(-100%)' : 'translateX(-50%)'}}>{utcTick(tick, span)}</span>)}</div></div>
      {lanes.map(lane => <div className="timeline-lane" key={lane}><b>{lane}</b><div className="timeline-track">{items.filter(i => sourceLabel(i.source_type) + ' / ' + (i.sensor ?? '未提供设备') === lane).map(i => <button aria-label={`时间线 ${kindLabel(i.kind)} ${i.id}`} className={i.kind === 'node' ? 'timeline-node' : 'timeline-alert'} key={i.id} onClick={() => choose(i)} style={{left: `${position(i.event_time)}%`}} title={`${kindLabel(i.kind)} ${i.event_time} ${i.id}`} type="button"><TimelineMarker kind={i.kind}/></button>)}</div></div>)}</div></div>
      <p className="muted timeline-hint">当前页 {items.length} / {total} 个对象显示在轨道上；拖动缩放可展开密集时间段。</p>
      <div className="table-scroll"><table><thead><tr><th>时间 / UTC</th><th>来源 / 设备</th><th>已有对象</th><th>引用</th></tr></thead><tbody>{items.map(i => <tr key={`${i.id}/${sourceLabel(i.source_type)}/${i.sensor}`}><td><Time value={i.event_time}/>{i.end_time !== i.event_time && <><br/><Time value={i.end_time}/></>}</td><td>{sourceLabel(i.source_type)} · {i.sensor ?? '未提供'}</td><td>{kindLabel(i.kind)}</td><td><button className="text-button" onClick={() => choose(i)} type="button"><StableId copy={false} label="时间线对象 ID" value={i.id}/></button></td></tr>)}</tbody></table></div></> : <EmptyState description="当前时间线分页没有可操作的告警或节点。" title="当前页没有时间线对象。"/>)}
    {resource.data && <Pager page={page} total={resource.data.total} onChange={changePage}/>}
  </Section>;
}
