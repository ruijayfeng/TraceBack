import {severityLabel, sourceLabel, entityLabel, incidentKindLabel, statusLabel} from '../lib/displayLabels';
import {shortId} from '../lib/ids';
import {api} from '../api/client';
import {useResource} from '../api/hooks';
import type {IncidentRow} from '../types/domain';
import {useState} from 'react';
import {AIStatus, Notice, Pager, Section, Time} from '../components/common';
import {Button} from '../components/ui/button';
import {CopyButton} from '../components/ui/copy-id';
import {EmptyState} from '../components/ui/empty-state';
import {ErrorState} from '../components/ui/error-state';
import {Skeleton} from '../components/ui/skeleton';
import {Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow} from '../components/ui/table';
import {TraceIcon} from '../components/ui/trace-icon';
import {ChevronRight, Download, Search, X} from 'lucide-react';
import {DEFAULT_FILTERS, type ListFilters} from '../lib/route';
import {useMediaQuery} from '../lib/useMediaQuery';
import {downloadTextFile, incidentsToCsv} from '../lib/csv';
import {readableEntityValue} from '../lib/format';
import {notify} from '../components/ui/toast';
export type {ListFilters} from '../lib/route';

const KIND_LABELS: [string, string][] = [['all','全部'],['singleton','单代表告警事件'],['multi_alert','关联聚合事件'],['has_chain','有向攻击链'],['ai_explained','AI 已研判'],['ai_pending','AI 待处理或不可用']];
const SORT_LABELS: [string, string][] = [['time','最新观察时间'],['alert_count','告警数量'],['node_count','节点数量']];
const SEVERITY_ORDER = ['critical','high','medium','low','informational','unknown'];

function matchesQuery(row: IncidentRow, query: string): boolean {
  if (!query) return true;
  const haystack = [row.incident.incident_id, row.incident.severity, row.incident.status, row.incident.summary ?? '', ...row.sources, ...row.techniques, ...row.entities.flatMap(e => [e.type, e.value, e.display_value ?? ''])].join(' ').toLowerCase();
  return haystack.includes(query);
}

function TableTimeRange({start, end}: {start: string; end: string}) {
  const from = start.replace('T', ' ').replace('Z', '');
  const to = end.replace('T', ' ').replace('Z', '');
  if (from === to) return <div className="cell-time"><time dateTime={start} title={start}>{from}</time></div>;
  const sameDate = from.slice(0, 10) === to.slice(0, 10);
  return <div className="cell-time">
    <time dateTime={start} title={start}>{from}</time>
    <time dateTime={end} title={end}><span aria-hidden className="range-arrow">→ </span>{sameDate ? to.slice(11) : to}</time>
  </div>;
}
const toInputValue = (iso: string) => iso ? iso.slice(0, 16) : '';
const fromInputValue = (local: string) => local ? (local.length === 16 ? `${local}:00.000Z` : `${local}.000Z`) : '';

export type TableDensity = 'comfortable' | 'compact';

export function IncidentTable({rows, onOpen, density = 'comfortable'}: {rows: IncidentRow[]; onOpen: (i: string) => void; density?: TableDensity}) {
  const narrow = useMediaQuery('(max-width: 640px)');
  const compact = useMediaQuery('(max-width: 1280px)');
  if (narrow || compact) {
    return <ul className="mobile-list">
      {rows.map(r => <li key={r.incident.incident_id}>
        <button aria-label="查看详情 →" className="mobile-row" onClick={() => onOpen(r.incident.incident_id)} type="button">
          <span className="mobile-row-top">
            <span className={'severity severity-' + r.incident.severity}>{severityLabel(r.incident.severity)}</span>
            <span className="cell-title">{r.incident.summary || incidentKindLabel(r.representative_member_count)}</span>
            <TraceIcon className="mobile-row-chevron" icon={ChevronRight} size={16}/>
          </span>
          <span className="mobile-row-meta">
            <span><b>{r.representative_member_count ?? '未提供'}</b> 代表</span>
            <span>{r.expanded_member_count ?? r.alert_count} 告警</span>
            <span>{r.node_count} 节点</span>
            <span>{r.edge_count} 边</span>
            <span>{r.sources.map(sourceLabel).join(' · ')}</span>
            <span>{r.representative_member_count === 1 ? '单代表' : r.representative_member_count === undefined ? '类型未提供' : '聚合'}</span>
            <span>{statusLabel(r.incident.status)}</span>
            <span>{r.incident.start_time.slice(0, 19).replace('T', ' ')} UTC</span>
          </span>
        </button>
      </li>)}
    </ul>;
  }
  return <>
    <div aria-label="安全事件列表表格" className={'table-frame table-density-' + density} role="region" tabIndex={0}>
      <Table className="list-table" render={<div className="contents" />}>
        <colgroup><col className="col-incident"/><col className="col-time"/><col className="col-counts"/><col className="col-entities"/><col className="col-ai"/><col className="col-action"/></colgroup>
        <TableCaption className="sr-only">安全事件列表，共 {rows.length} 条</TableCaption>
        <TableHeader><TableRow><TableHead>事件与状态</TableHead><TableHead>观察时间 · UTC</TableHead><TableHead>成员与规模</TableHead><TableHead>实体与来源</TableHead><TableHead>研判 / ATT&amp;CK</TableHead><TableHead>操作</TableHead></TableRow></TableHeader>
        <TableBody>{rows.map(r => <TableRow
          aria-label={`打开安全事件 ${r.incident.incident_id}`}
          key={r.incident.incident_id}
          onClick={event => {if (!(event.target as HTMLElement).closest('button,a,input,select,summary')) onOpen(r.incident.incident_id);}}
          onKeyDown={event => {if (event.key === 'Enter' || event.key === ' ') {event.preventDefault();onOpen(r.incident.incident_id);}}}
          tabIndex={0}
        >
          <TableCell>
            <div className="cell-content">
              <p className="cell-title" title={r.incident.summary ?? undefined}>{r.incident.summary || incidentKindLabel(r.representative_member_count)}</p>
              <div className="cell-subline">
                <span className={'severity severity-' + r.incident.severity}>{severityLabel(r.incident.severity)}</span>
                <span>{incidentKindLabel(r.representative_member_count)}</span>
                <span aria-hidden>·</span>
                <span>{statusLabel(r.incident.status)}</span>
                {r.edge_count > 0 && <><span aria-hidden>·</span><span>有向攻击链</span></>}
              </div>
              <div className="cell-id"><code title={r.incident.incident_id}>{shortId(r.incident.incident_id)}</code><CopyButton label="安全事件 ID" value={r.incident.incident_id}/></div>
            </div>
          </TableCell>
          <TableCell><TableTimeRange end={r.incident.end_time} start={r.incident.start_time}/></TableCell>
          <TableCell>
            <div className="cell-sub" title={`${r.representative_member_count ?? '未提供'} 去重代表 · ${r.expanded_member_count ?? r.alert_count} 展开告警`}><b>{r.representative_member_count ?? '未提供'}</b> 去重 · <b>{r.expanded_member_count ?? r.alert_count}</b> 展开</div>
            <div className="cell-sub">{r.node_count} 节点 · {r.edge_count} 边{r.has_dedupe_expansion && <><span aria-hidden> · </span><span>含去重展开</span></>}</div>
          </TableCell>
          <TableCell>
            <div className="cell-entities">
              <div>{r.sources.map(sourceLabel).join(' · ')}</div>
              {r.entities.slice(0, 2).map(e => <div key={e.entity_id} title={e.value}><b>{entityLabel(e.type)}</b> {readableEntityValue(e.display_value ?? e.value)}</div>)}
              {r.entities.length > 2 && <small>另 {r.entities.length - 2} 个实体</small>}
            </div>
          </TableCell>
          <TableCell>
            <div className="cell-sub"><AIStatus state={r.ai_state}/></div>
            <div className="cell-sub" title={r.techniques.length ? r.techniques.join(' · ') : '无已验证 ATT&CK 技术'}>{r.techniques.length ? r.techniques.join(' · ') : '无已验证技术'}</div>
          </TableCell>
          <TableCell><div className="cell-content-end"><Button aria-label="查看详情 →" onClick={event => {event.stopPropagation();onOpen(r.incident.incident_id);}} size="xs" type="button" variant="ghost">查看详情<TraceIcon icon={ChevronRight} size={13}/></Button></div></TableCell>
        </TableRow>)}</TableBody>
      </Table>
    </div>
  </>;
}

export default function IncidentList({analysisId, filters, onFilters, onOpen, revision}: {analysisId: string; filters: ListFilters; onFilters: (f: ListFilters) => void; onOpen: (i: string) => void; revision: number}) {
  const {page = 1, pageSize = 20, kind = 'all', sort = 'time', severity = '', q = '', entity = '', startTime = '', endTime = ''} = filters;
  const [density, setDensity] = useState<TableDensity>(() => {
    try {return window.localStorage.getItem('traceback.tableDensity') === 'compact' ? 'compact' : 'comfortable';} catch {return 'comfortable';}
  });
  function changeDensity(next: TableDensity) {
    setDensity(next);
    try {window.localStorage.setItem('traceback.tableDensity', next);} catch { /* storage unavailable */ }
  }
  const narrow = useMediaQuery('(max-width: 720px)');
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
  if (severity) chips.push({label: `观测等级：${severityLabel(severity)}`, clear: () => onFilters({...filters,severity:'',page:1})});
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
  const activeFilterCount = [kind !== 'all', sort !== 'time', Boolean(severity), Boolean(startTime), Boolean(endTime)].filter(Boolean).length;
  const FILTER_CONTROLS = <>

          <label className="field"><span>事件类型</span><select aria-label="事件类型" onChange={e => onFilters({...filters, kind: e.target.value, page: 1})} value={kind}>{KIND_LABELS.map(([value,label]) => <option key={value} value={value}>{label}</option>)}</select></label>
          <label className="field"><span>排序</span><select aria-label="排序" onChange={e => onFilters({...filters,sort:e.target.value,page:1})} value={sort}>{SORT_LABELS.map(([value,label]) => <option key={value} value={value}>{label}</option>)}</select></label>
          <label className="field"><span>观测等级</span><select aria-label="观测等级" onChange={e => onFilters({...filters,severity:e.target.value,page:1})} value={severity}><option value="">全部等级</option>{SEVERITY_ORDER.map(v => <option key={v} value={v}>{severityLabel(v)}</option>)}</select></label>
          <div className="time-range">
            <label className="field field-time"><span>开始时间 · UTC</span><input aria-label="开始时间" onChange={event => onFilters({...filters,startTime:fromInputValue(event.target.value),page:1})} step="1" type="datetime-local" value={toInputValue(startTime)}/></label>
            <label className="field field-time"><span>结束时间 · UTC</span><input aria-label="结束时间" onChange={event => onFilters({...filters,endTime:fromInputValue(event.target.value),page:1})} step="1" type="datetime-local" value={toInputValue(endTime)}/></label>
            {(startTime || endTime) && <button className="text-action field-clear" onClick={() => onFilters({...filters,startTime:'',endTime:'',page:1})} type="button">清除时间</button>}
          </div>
          {filtersActive && <button className="text-action field-clear" onClick={clearFilters} type="button">清除全部筛选</button>}
  </>;
  return <Section
    actions={<>
      <span className="list-count">{q || entity ? `匹配 ${resource.data?.total?.toLocaleString() ?? '…'} 条` : `第 ${page} 页 · 共 ${resource.data?.total?.toLocaleString() ?? '…'} 条`}{resource.loading ? ' · 更新中…' : ''}</span>
      <div aria-label="表格密度" className="segmented" role="group">
        <button aria-current={density === 'comfortable' ? 'page' : undefined} onClick={() => changeDensity('comfortable')} type="button">舒适</button>
        <button aria-current={density === 'compact' ? 'page' : undefined} onClick={() => changeDensity('compact')} type="button">紧凑</button>
      </div>
      <Button disabled={!rows.length} onClick={exportCsv} size="xs" type="button" variant="outline"><TraceIcon icon={Download} size={13}/>导出当前页 CSV</Button>
    </>}
    className="list-section"
    hint="按观测等级筛选 · 不做额外风险评分"
    id="incident-list"
    title="安全事件列表"
  >
    <div className="list-toolbar">
      <div className="toolbar-row">
        <div className="toolbar-search">
          <div className="tb-search-input">
            <TraceIcon icon={Search} size={14}/>
            <input aria-label="搜索当前页" onChange={event => onFilters({...filters,q:event.target.value,page:1})} placeholder="事件 ID、来源、规则、ATT&CK" type="search" value={q}/>
          </div>
          {!narrow && <div className="tb-search-input">
            <TraceIcon icon={Search} size={14}/>
            <input aria-label="搜索实体" onChange={event => onFilters({...filters,entity:event.target.value,page:1})} placeholder="主机、IP、账号、进程名" type="search" value={entity}/>
          </div>}
        </div>
        {narrow
          ? <details className="mobile-filters"><summary>实体与筛选{activeFilterCount ? ` · ${activeFilterCount}` : ''}</summary><div className="toolbar-filters">
              <label className="field"><span>搜索实体</span><input aria-label="搜索实体" onChange={event => onFilters({...filters,entity:event.target.value,page:1})} placeholder="主机、IP、账号、进程名" type="search" value={entity}/></label>
              {FILTER_CONTROLS}
            </div></details>
          : <div className="toolbar-filters">{FILTER_CONTROLS}</div>}
      </div>
    </div>
    {chips.length > 0 && <div aria-label="当前筛选" className="chips">{chips.map(chip => <span className="chip" key={chip.label}><span>{chip.label}</span><button aria-label={`清除筛选：${chip.label}`} onClick={chip.clear} type="button"><TraceIcon icon={X} size={11}/></button></span>)}</div>}
    {firstLoad && <Notice kind="loading">正在读取安全事件列表…</Notice>}
    {resource.error ? <ErrorState error={resource.error} onRetry={resource.reload} scope="安全事件列表"/> : resource.data ? <>
      {rows.length
        ? <>{resource.loading && <p className="muted-text" role="status" style={{fontSize: 12}}>正在更新第 {page} 页…</p>}<IncidentTable density={density} onOpen={onOpen} rows={rows}/></>
        : <EmptyState
            action={filtersActive ? <Button onClick={clearFilters} size="sm" type="button" variant="outline">清除筛选</Button> : undefined}
            description={query || entity ? '没有匹配关键词或实体的事件；可清除搜索，或改用更短的关键词。' : filtersActive ? '当前筛选或页码下没有匹配事件，可清除筛选后重试。' : '该分析快照中没有可展示的安全事件。'}
            title={query ? `没有匹配“${q}”的安全事件。` : entity ? `没有匹配实体“${entity}”的安全事件。` : resource.data.total === 0 ? '当前筛选下没有安全事件。' : '当前页没有安全事件。'}
          />}
      <Pager page={page} size={pageSize} total={resource.data.total} onChange={p => onFilters({...filters,page:p})} onSizeChange={size => onFilters({...filters,pageSize:size,page:1})}/>
    </> : resource.loading ? <div aria-busy="true" role="status"><Skeleton className="h-9 w-full"/><Skeleton className="mt-2 h-9 w-full"/></div> : null}
  </Section>;
}
