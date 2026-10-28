import {categoryLabel, severityLabel, sourceLabel, fieldLabel, entityLabel} from '../../lib/displayLabels';
import {shortId} from '../../lib/ids';
import {X} from 'lucide-react';
import {useMemo, useRef, useState} from 'react';
import {api} from '../../api/client';
import {useResource} from '../../api/hooks';
import type {AlertDetail, EvidenceSelection} from '../../types/domain';
import {JsonView, Notice, StableId, Time} from '../common';
import {EmptyState} from '../ui/empty-state';
import {ErrorState} from '../ui/error-state';
import {Sheet, SheetClose, SheetDescription, SheetPanel, SheetPopup, SheetTitle} from '../ui/sheet';
import {TextSkeleton} from '../ui/skeleton';
import {TraceIcon} from '../ui/trace-icon';

const OBJECT_KIND: [string, string][] = [['inc_', '安全事件'], ['nod_', '攻击链节点'], ['che_', '攻击链边'], ['alt_', '设备告警'], ['ent_', '实体'], ['ana_', '分析']];
function objectKind(id: string) {return OBJECT_KIND.find(([prefix]) => id.startsWith(prefix))?.[1] ?? '证据对象';}

function alertOptionLabel(alert: AlertDetail | undefined, id: string) {
  if (!alert) return shortId(id);
  return `${sourceLabel(alert.alert.source_type)} · ${alert.alert.timestamp.slice(0, 19).replace('T', ' ')} · ${alert.alert.rule_id ?? '规则未提供'}`;
}

export function EvidencePanel({analysisId, selection, onClose}: {analysisId: string; selection: EvidenceSelection; onClose: () => void}) {
  const [active, setActive] = useState(selection.alertIds[0] ?? '');
  const [query, setQuery] = useState('');
  const listRef = useRef<HTMLDivElement>(null);
  const resource = useResource(signal => active ? api.alert(analysisId, active, signal) : Promise.resolve(null), [analysisId, active], {keepPrevious:true});
  const options = useResource<AlertDetail[]>(signal => selection.alertIds.length ? Promise.all(selection.alertIds.map(id => api.alert(analysisId, id, signal))) : Promise.resolve([]), [analysisId, selection.alertIds.join(',')]);
  const optionsById = useMemo(() => new Map((options.data ?? []).map(alert => [alert.alert.alert_id, alert])), [options.data]);
  const data = resource.data;
  const pointers = selection.pointers?.filter(p => p.alert_id === active) ?? [];
  const filteredIds = selection.alertIds.filter(id => !query || (id + ' ' + alertOptionLabel(optionsById.get(id), id)).toLowerCase().includes(query.toLowerCase()));
  const kind = objectKind(selection.objectId);
  function moveActive(direction: 1 | -1) {
    const index = filteredIds.indexOf(active);
    const next = filteredIds[Math.max(0, Math.min(filteredIds.length - 1, index + direction))];
    if (next) setActive(next);
  }
  return <Sheet onOpenChange={open => {if (!open) onClose();}} open>
    <SheetPopup aria-label="证据面板" className="evidence-drawer" showCloseButton={false} side="right">
      <div className="sticky top-0 z-10 border-b border-border bg-popover px-5 py-4">
        <nav aria-label="证据面包屑" className="detail-breadcrumbs"><span>安全事件</span><span aria-hidden>/</span><span>{kind}</span><span aria-hidden>/</span><span aria-current="page">证据</span></nav>
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0"><span className="eyebrow">证据 / 设备告警事实</span><SheetTitle className="mt-1 break-words text-lg">{selection.title}</SheetTitle><SheetDescription className="sr-only">{kind}的设备告警证据与字段指针</SheetDescription></div>
          <SheetClose aria-label="关闭证据" className="inline-flex size-9 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-accent-foreground focus-visible:ring-2 focus-visible:ring-ring" type="button"><TraceIcon icon={X} size={20}/></SheetClose>
        </div>
        <div className="detail-badges"><span className="badge">{kind}</span><StableId label={`${kind} ID`} value={selection.objectId}/><span className="muted">分析</span><StableId label="分析 ID" value={analysisId}/></div>
      </div>
      <SheetPanel>
        {selection.alertIds.length ? <div className="alert-picker">
          <label className="alert-search">搜索支撑告警<input aria-label="搜索支撑告警" onChange={event => setQuery(event.target.value)} placeholder="按来源、规则、时间或 ID 过滤" type="search" value={query}/></label>
          <div aria-label="支撑告警" className="alert-options" ref={listRef} role="listbox" tabIndex={-1}>
            {filteredIds.length ? filteredIds.map(id => <div aria-selected={id === active} className={id === active ? 'alert-option selected' : 'alert-option'} key={id} onClick={() => setActive(id)} onKeyDown={event => {if (event.key === 'Enter' || event.key === ' ') {event.preventDefault();setActive(id);} else if (event.key === 'ArrowDown') {event.preventDefault();moveActive(1);} else if (event.key === 'ArrowUp') {event.preventDefault();moveActive(-1);}}} role="option" tabIndex={0}>
              <span className="alert-option-id">{shortId(id)}</span>
              <span className="alert-option-meta">{options.loading ? '正在读取告警元数据…' : alertOptionLabel(optionsById.get(id), id)}</span>
            </div>) : <p className="muted">没有匹配的支撑告警。</p>}
          </div>
          {options.error && <p className="muted">告警元数据暂不可读取，仍可按 ID 选择。</p>}
        </div> : <EmptyState description="该对象没有绑定设备告警，只能查看字段指针或实体。" title="没有可读取的支撑告警。"/>}
        {resource.loading && !data && <TextSkeleton lines={4}/>}
        {resource.loading && !data && <Notice kind="loading">正在读取证据…</Notice>}
        {resource.error && <ErrorState error={resource.error} onRetry={resource.reload} scope="设备告警证据"/>}
        {data && data.analysis_id !== analysisId && <Notice kind="error">证据快照不匹配。</Notice>}
        {data && data.analysis_id === analysisId && <><dl className="facts"><dt>告警 ID / 标准化引用</dt><dd><StableId label="告警 ID" value={data.alert.alert_id}/></dd><dt>来源</dt><dd>{sourceLabel(data.alert.source_type)} · {data.alert.sensor ?? data.alert.source_namespace}</dd><dt>观测时间</dt><dd><Time value={data.alert.timestamp}/></dd><dt>规则 / 特征</dt><dd>{data.alert.rule_id ?? '未提供'}{data.alert.signature && ' · ' + data.alert.signature}</dd><dt>设备观测等级 / 类别</dt><dd>{severityLabel(data.alert.severity)} · {categoryLabel(data.alert.category)}</dd></dl>
          {pointers.length > 0 && <div><h3>绑定证据指针</h3>{pointers.map((p, i) => <p key={i}><code>{p.pointer || '(root)'}</code> · side={p.side}<br/><StableId label="告警 ID" value={p.alert_id}/></p>)}</div>}
          <h3>相关字段</h3><dl className="facts">{Object.entries(data.alert.field_provenance).sort(([a],[b]) => a.localeCompare(b)).map(([field, provenance]) => <div key={field}><dt>{fieldLabel(field)}</dt><dd>{formatField(data.alert[field as keyof typeof data.alert])}<br/><code>{provenance.raw_pointer || '(root)'}</code><small className="muted"> · {provenance.transform}</small></dd></div>)}</dl>
          <h3>实体</h3>{data.entities.length ? <ul className="entities">{data.entities.map(e => <li key={e.entity_id}><b>{entityLabel(e.type)}</b> {e.display_value ?? e.value}<small>{e.scope}</small></li>)}</ul> : <Notice>该告警未抽取实体。</Notice>}
          <details className="raw-evidence"><summary>原始设备告警 / raw_alert</summary><JsonView value={data.alert.raw_alert} title="raw_alert"/></details>
          <details><summary>标准化告警完整引用</summary><JsonView value={{...data.alert, raw_alert: '[see raw_alert above]'}}/></details>
          <p className="muted">告警存在及其字段属于设备观测事实；告警本身不代表入侵已确认。</p></>}
      </SheetPanel>
    </SheetPopup>
  </Sheet>;
}
function formatField(value: unknown) {if (value === null || value === undefined) return '该字段未提供'; if (typeof value === 'object') return JSON.stringify(value).slice(0, 800); return String(value).slice(0, 800);}
