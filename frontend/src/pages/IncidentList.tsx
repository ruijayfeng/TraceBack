import {severityLabel, sourceLabel, entityLabel, incidentKindLabel, statusLabel} from '../lib/displayLabels';
import {shortId} from '../lib/ids';
import {api} from '../api/client';
import {useResource} from '../api/hooks';
import type {IncidentRow} from '../types/domain';
import {AIStatus, Notice, Pager, Time} from '../components/common';
import {CopyButton} from '../components/ui/copy-id';
import {EmptyState} from '../components/ui/empty-state';
import {ErrorState} from '../components/ui/error-state';
import {TableSkeleton} from '../components/ui/skeleton';
import {Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow} from '../components/ui/table';
import {TraceIcon} from '../components/ui/trace-icon';
import {ChevronRight, Download, X} from 'lucide-react';
import {DEFAULT_FILTERS, type ListFilters} from '../lib/route';
import {downloadTextFile, incidentsToCsv} from '../lib/csv';
import {notify} from '../components/ui/toast';
export type {ListFilters} from '../lib/route';

const KIND_LABELS: [string, string][] = [['all','全部'],['singleton','单代表告警事件'],['multi_alert','关联聚合事件'],['has_chain','有向攻击链'],['ai_explained','AI 已研判'],['ai_pending','AI 待处理或不可用']];
const SORT_LABELS: [string, string][] = [['time','最新观察时间'],['alert_count','告警数量'],['node_count','节点数量']];
const SEVERITY_ORDER = ['critical','high','medium','low','informational','unknown'];

/** Entity values may be JSON objects from raw device data; render a readable projection, keep the raw value in title. */
function readableEntityValue(value: string): string {
  if (!value.startsWith('{')) return value;
  try {
    const parsed = JSON.parse(value) as Record<string, unknown>;
    const parts = [parsed.name, parsed.host, parsed.ip, parsed.account, parsed.command, parsed.path].filter(v => typeof v === 'string' && v);
    if (typeof parsed.pid === 'number' || typeof parsed.pid === 'string') parts.push(`pid ${parsed.pid}`);
    return parts.length ? parts.join(' · ') : value;
  } catch { return value; }
}

function matchesQuery(row: IncidentRow, query: string): boolean {
  if (!query) return true;
  const haystack = [row.incident.incident_id, row.incident.severity, row.incident.status, row.incident.summary ?? '', ...row.sources, ...row.techniques, ...row.entities.flatMap(e => [e.type, e.value, e.display_value ?? ''])].join(' ').toLowerCase();
  return haystack.includes(query);
}

const toInputValue = (iso: string) => iso ? iso.slice(0, 16) : '';
const fromInputValue = (local: string) => local ? (local.length === 16 ? `${local}:00.000Z` : `${local}.000Z`) : '';

export function IncidentTable({rows, onOpen}: {rows: IncidentRow[]; onOpen: (i: string) => void}) {
  return <Table className="incident-table" render={<div className="table-scroll table-scroll-list" tabIndex={0} />}>
    <TableCaption className="sr-only">安全事件列表，共 {rows.length} 条</TableCaption>
    <TableHeader><TableRow><TableHead>安全事件 / 状态</TableHead><TableHead>观察区间 · UTC</TableHead><TableHead>告警 / 节点 / 边</TableHead><TableHead>实体 / 来源</TableHead><TableHead>AI / ATT&amp;CK</TableHead><TableHead>调查</TableHead></TableRow></TableHeader>
    <TableBody>{rows.map(r => <TableRow
      aria-label={`打开安全事件 ${r.incident.incident_id}`}
      key={r.incident.incident_id}
      onClick={event => {if (!(event.target as HTMLElement).closest('button,a,input,select,summary')) onOpen(r.incident.incident_id);}}
      onKeyDown={event => {if (event.key === 'Enter' || event.key === ' ') {event.preventDefault();onOpen(r.incident.incident_id);}}}
      tabIndex={0}
    >
      <TableCell data-label="安全事件 / 状态"><div className="cell-content"><div className="flex items-center gap-1"><button className="text-button font-mono text-xs" onClick={() => onOpen(r.incident.incident_id)} title={r.incident.incident_id} type="button"><code>{shortId(r.incident.incident_id)}</code></button><CopyButton label="安全事件 ID" value={r.incident.incident_id}/></div><div className="mt-1 flex flex-wrap gap-1"><span className={'severity severity-' + r.incident.severity}>{severityLabel(r.incident.severity)}</span><span className="badge">{incidentKindLabel(r.representative_member_count)}</span><span className="badge badge-status">{statusLabel(r.incident.status)}</span>{r.edge_count > 0 && <span className="badge">有向攻击链</span>}</div>{r.incident.summary && <p className="incident-summary" title={r.incident.summary}>{r.incident.summary}</p>}</div></TableCell>
      <TableCell data-label="观察区间 · UTC"><div className="cell-content"><Time value={r.incident.start_time}/><br/><Time value={r.incident.end_time}/></div></TableCell>
      <TableCell data-label="告警 / 节点 / 边"><div className="cell-content"><b>{r.representative_member_count ?? '未提供'}</b> 去重代表 · {r.expanded_member_count ?? r.alert_count} 展开告警<div className="mt-1">{r.has_dedupe_expansion && <span className="badge">含去重展开</span>}{r.node_count} 节点 · {r.edge_count} 边</div></div></TableCell>
      <TableCell data-label="实体 / 来源"><div className="cell-content"><div>{r.sources.map(sourceLabel).join(' · ')}</div>{r.entities.slice(0, 3).map(e => <div key={e.entity_id} title={e.value}><b>{entityLabel(e.type)}</b> {readableEntityValue(e.display_value ?? e.value)}</div>)}{r.entities.length > 3 && <small className="muted">另 {r.entities.length - 3} 个实体 · 详情可查看</small>}</div></TableCell>
      <TableCell data-label="AI / ATT&amp;CK"><div className="cell-content"><AIStatus state={r.ai_state}/><div>{r.techniques.length ? r.techniques.join(' · ') : '无已验证 ATT&CK 技术'}</div></div></TableCell>
      <TableCell data-label="调查"><div className="cell-content cell-content-end"><button aria-label="查看详情 →" onClick={() => onOpen(r.incident.incident_id)} type="button"><span className="inline-flex items-center gap-1">查看详情<TraceIcon icon={ChevronRight} size={14}/></span></button></div></TableCell>
    </TableRow>)}</TableBody>
  </Table>;
}

export default function IncidentList({analysisId, filters, onFilters, onOpen, revision}: {analysisId: string; filters: ListFilters; onFilters: (f: ListFilters) => void; onOpen: (i: string) => void; revision: number}) {
  const {page = 1, pageSize = 20, kind = 'all', sort = 'time', severity = '', q = '', entity = '', startTime = '', endTime = ''} = filters;
  const resource = useResource(signal => api.incidents(analysisId,page,kind,sort,severity,pageSize,q,entity,startTime,endTime,signal), [analysisId,page,pageSize,kind,sort,severity,q,entity,startTime,endTime,revision], {keepPrevious:true});
  const firstLoad = resource.loading && !resource.data;
  const query = q.trim().toLowerCase();
  const allRows = resource.data?.items ?? [];
  const rows = allRows.filter(row => matchesQuery(row, query));
  const filtersActive = kind !== 'all' || sort !== 'time' || Boolean(severity) || Boolean(q) || Boolean(entity) || Boolean(startTime) || Boolean(endTime) || page > 1 || pageSize !== 20;
  const clearFilters = () => onFilters({...DEFAULT_FILTERS});
  const chips: {label: string; clear: () => void}[] = [];
  if (kind !== 'all') chips.push({label: `类型：${KIND_LABELS.find(([v]) => v === kind)?.[1] ?? kind}`, clear: () => onFilters({...filters,kind:'all',page:1})});
  if (sort !== 'time') chips.push({label: `排序：${SORT_LABELS.find(([v]) => v === sort)?.[1] ?? sort}`, clear: () => onFilters({...filters,sort:'time',page:1})});
  if (severity) chips.push({label: `设备等级：${severityLabel(severity)}`, clear: () => onFilters({...filters,severity:'',page:1})});
  if (q) chips.push({label: `搜索：${q}`, clear: () => onFilters({...filters,q:'',page:1})});
  if (entity) chips.push({label: `实体：${entity}`, clear: () => onFilters({...filters,entity:'',page:1})});
  if (startTime) chips.push({label: `开始 ≥ ${startTime.slice(0, 16).replace('T', ' ')}Z`, clear: () => onFilters({...filters,startTime:'',page:1})});
  if (endTime) chips.push({label: `结束 < ${endTime.slice(0, 16).replace('T', ' ')}Z`, clear: () => onFilters({...filters,endTime:'',page:1})});
  if (pageSize !== 20) chips.push({label: `每页 ${pageSize} 条`, clear: () => onFilters({...filters,pageSize:20,page:1})});
  function exportCsv() {
    try {
      downloadTextFile(`incidents_${analysisId.slice(4, 12)}.csv`, incidentsToCsv(rows));
      notify.success(`已导出当前页 ${rows.length} 条事件`);
    } catch {notify.error('导出失败，请重试');}
  }
  return <section aria-busy={resource.loading || undefined} className="panel" id="incident-list">
    <div className="section-heading"><h2>安全事件列表</h2><span className="muted">按设备等级筛选 · 无额外风险评分</span></div>
    <div className="list-toolbar">
      <label className="search-field">关键词搜索<input aria-label="搜索当前页" onChange={event => onFilters({...filters,q:event.target.value,page:1})} placeholder="事件 ID、来源、规则、ATT&CK" type="search" value={q}/></label>
      <label className="search-field entity-field">实体搜索<input aria-label="搜索实体" onChange={event => onFilters({...filters,entity:event.target.value,page:1})} placeholder="主机、IP、账号、进程名" type="search" value={entity}/></label>
      <div className="time-filters">
        <label>开始时间 · UTC<input aria-label="开始时间" onChange={event => onFilters({...filters,startTime:fromInputValue(event.target.value),page:1})} step="1" type="datetime-local" value={toInputValue(startTime)}/></label>
        <label>结束时间 · UTC<input aria-label="结束时间" onChange={event => onFilters({...filters,endTime:fromInputValue(event.target.value),page:1})} step="1" type="datetime-local" value={toInputValue(endTime)}/></label>
      </div>
      <span className="muted list-count">{q || entity ? `匹配 ${resource.data?.total?.toLocaleString() ?? '…'} 条` : `第 ${page} 页 · 共 ${resource.data?.total?.toLocaleString() ?? '…'} 条`}{resource.loading ? ' · 更新中…' : ''}</span>
      <button disabled={!rows.length} onClick={exportCsv} type="button"><TraceIcon icon={Download} size={14}/>导出当前页 CSV</button>
    </div>
    <div className="filters">
      <label>事件类型<select value={kind} onChange={e => onFilters({...filters, kind: e.target.value, page: 1})}>{KIND_LABELS.map(([value,label]) => <option key={value} value={value}>{label}</option>)}</select></label>
      <label>排序<select value={sort} onChange={e => onFilters({...filters,sort:e.target.value,page:1})}>{SORT_LABELS.map(([value,label]) => <option key={value} value={value}>{label}</option>)}</select></label>
      <label>设备等级<select value={severity} onChange={e => onFilters({...filters,severity:e.target.value,page:1})}><option value="">全部等级</option>{SEVERITY_ORDER.map(v => <option key={v} value={v}>{severityLabel(v)}</option>)}</select></label>
      {filtersActive && <button className="clear-filters" onClick={clearFilters} type="button">清除全部筛选</button>}
    </div>
    {chips.length > 0 && <div aria-label="当前筛选" className="filter-chips">{chips.map(chip => <button className="filter-chip" key={chip.label} onClick={chip.clear} type="button"><span>{chip.label}</span><TraceIcon aria-hidden icon={X} size={12}/><span className="sr-only">，点击清除</span></button>)}</div>}
    {firstLoad && <Notice kind="loading">正在读取安全事件列表…</Notice>}
    {resource.error ? <ErrorState error={resource.error} onRetry={resource.reload} scope="安全事件列表"/> : resource.data ? <>
      {rows.length
        ? <>{resource.loading && <p className="muted" role="status">正在更新第 {page} 页…</p>}<IncidentTable onOpen={onOpen} rows={rows}/></>
        : <EmptyState
            description={query || entity ? '没有匹配关键词或实体的事件；可清除搜索，或改用更短的关键词。' : filtersActive ? '当前筛选或页码下没有匹配事件，可清除筛选后重试。' : '该分析快照中没有可展示的安全事件。'}
            title={query ? `没有匹配“${q}”的安全事件。` : entity ? `没有匹配实体“${entity}”的安全事件。` : resource.data.total === 0 ? '当前筛选下没有安全事件。' : '当前页没有安全事件。'}
            action={filtersActive ? <button onClick={clearFilters} type="button">清除筛选</button> : undefined}
          />}
      <Pager page={page} size={pageSize} total={resource.data.total} onChange={p => onFilters({...filters,page:p})} onSizeChange={size => onFilters({...filters,pageSize:size,page:1})}/>
    </> : resource.loading ? <TableSkeleton/> : null}
  </section>;
}
