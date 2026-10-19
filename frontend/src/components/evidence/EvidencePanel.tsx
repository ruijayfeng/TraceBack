import {categoryLabel, severityLabel, sourceLabel, fieldLabel, entityLabel} from '../../lib/displayLabels';
import {useState} from 'react';
import {api} from '../../api/client';
import {useResource} from '../../api/hooks';
import type {EvidenceSelection} from '../../types/domain';
import {JsonView, Notice, StableId, Time} from '../common';

export function EvidencePanel({analysisId, selection, onClose}: {analysisId: string; selection: EvidenceSelection; onClose: () => void}) {
  const [active, setActive] = useState(selection.alertIds[0] ?? '');
  const resource = useResource(signal => api.alert(analysisId, active, signal), [analysisId, active]);
  const data = resource.data;
  const pointers = selection.pointers?.filter(p => p.alert_id === active) ?? [];
  return <aside className="evidence-drawer" aria-label="证据面板"><div className="drawer-heading"><div><span className="eyebrow">证据 / 设备告警事实</span><h2>{selection.title}</h2></div><button onClick={onClose} aria-label="关闭证据">×</button></div>
    <p>支撑对象 <StableId value={selection.objectId}/></p><p>分析 <StableId value={analysisId}/></p>
    <label>支撑告警<select value={active} onChange={e => setActive(e.target.value)}>{selection.alertIds.map(a => <option key={a} value={a}>{a}</option>)}</select></label>
    {resource.loading && <Notice kind="loading">正在读取证据…</Notice>}{resource.error && <Notice kind="error">证据不可读取：{resource.error}</Notice>}
    {data && data.analysis_id !== analysisId && <Notice kind="error">证据快照不匹配。</Notice>}
    {data && data.analysis_id === analysisId && <><dl className="facts"><dt>告警 ID / 标准化引用</dt><dd><code>{data.alert.alert_id}</code></dd><dt>来源</dt><dd>{sourceLabel(data.alert.source_type)} · {data.alert.sensor ?? data.alert.source_namespace}</dd><dt>观测时间</dt><dd><Time value={data.alert.timestamp}/></dd><dt>规则 / 特征</dt><dd>{data.alert.rule_id ?? '未提供'}{data.alert.signature && ' · ' + data.alert.signature}</dd><dt>设备观测等级 / 类别</dt><dd>{severityLabel(data.alert.severity)} · {categoryLabel(data.alert.category)}</dd></dl>
      {pointers.length > 0 && <div><h3>绑定证据指针</h3>{pointers.map((p, i) => <p key={i}><code>{p.pointer || '(root)'}</code> · side={p.side}<br/><StableId value={p.alert_id}/></p>)}</div>}
      <h3>相关字段</h3><dl className="facts">{Object.entries(data.alert.field_provenance).sort(([a],[b]) => a.localeCompare(b)).map(([field, provenance]) => <div key={field}><dt>{fieldLabel(field)}</dt><dd>{formatField(data.alert[field as keyof typeof data.alert])}<br/><code>{provenance.raw_pointer || '(root)'}</code><small className="muted"> · {provenance.transform}</small></dd></div>)}</dl>
      <h3>实体</h3>{data.entities.length ? <ul className="entities">{data.entities.map(e => <li key={e.entity_id}><b>{entityLabel(e.type)}</b> {e.display_value ?? e.value}<small>{e.scope}</small></li>)}</ul> : <Notice>该告警未抽取实体。</Notice>}
      <details className="raw-evidence"><summary>原始设备告警 / raw_alert</summary><JsonView value={data.alert.raw_alert} title="raw_alert"/></details>
      <details><summary>标准化告警完整引用</summary><JsonView value={{...data.alert, raw_alert: '[see raw_alert above]'}}/></details>
      <p className="muted">告警存在及其字段属于设备观测事实；告警本身不代表入侵已确认。</p></>}
  </aside>;
}
function formatField(value: unknown) {if (value === null || value === undefined) return '该字段未提供'; if (typeof value === 'object') return JSON.stringify(value).slice(0, 800); return String(value).slice(0, 800);}
