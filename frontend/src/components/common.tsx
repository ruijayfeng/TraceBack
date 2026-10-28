import {aiLabel} from '../lib/displayLabels';
import {shortId} from '../lib/ids';
import {useEffect, useMemo, useRef, useState, type ReactNode} from 'react';
import {CopyId} from './ui/copy-id';
export {shortId};
export function StableId({value, label = 'ID', copy = true}: {value: string; label?: string; copy?: boolean}) {
  return <CopyId copy={copy} label={label} value={value}/>;
}
export function Time({value}: {value: string}) {return <time dateTime={value} title={value}>{value.replace('T', ' ').replace('Z', ' UTC')}</time>;}
export function Notice({kind = 'empty', children}: {kind?: 'empty' | 'loading' | 'error' | 'info'; children: ReactNode}) {
  return <div className={'notice ' + kind} role={kind === 'error' ? 'alert' : 'status'}>{children}</div>;
}
export function Section({title, hint, children, id}: {title: string; hint?: string; children: ReactNode; id?: string}) {return <section className="panel" id={id}><div className="section-heading"><h2>{title}</h2>{hint && <span className="muted">{hint}</span>}</div>{children}</section>;}
export function JsonView({value, title = '原始内容'}: {value: unknown; title?: string}) {
  const [expanded, setExpanded] = useState(false);
  const [visible, setVisible] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const element = ref.current;
    const details = element?.closest('details');
    if (!details) {setVisible(true);return;}
    const sync = () => setVisible(details.open);
    sync();
    details.addEventListener('toggle', sync);
    return () => details.removeEventListener('toggle', sync);
  }, []);
  const text = useMemo(() => visible ? JSON.stringify(value, null, 2) ?? '' : '', [value, visible]);
  return <div className="json-view" ref={ref}>{!visible ? <p className="muted">展开后读取并序列化原始内容，避免提前占用主线程。</p> : <><pre>{text.length > 2400 ? text.slice(0, 2400) + '\n… 已折叠' : text}</pre>{text.length > 2400 && <details onToggle={e => setExpanded(e.currentTarget.open)}><summary>展开 {title}（{text.length.toLocaleString()} 字符）</summary>{expanded && <pre>{text}</pre>}</details>}</>}</div>;
}
export function Pager({page, total, onChange, size = 20, onSizeChange}: {page: number; total: number; onChange: (p: number) => void; size?: number; onSizeChange?: (size: number) => void}) {
  const last = Math.max(1, Math.ceil(total / size));
  return <nav className="pager" aria-label="分页">
    <span className="pager-summary">{total.toLocaleString()} 条 · 第 {page} / {last} 页</span>
    {onSizeChange && <label className="pager-size">每页<select aria-label="每页数量" onChange={e => onSizeChange(Number(e.target.value))} value={size}>{[20,50,100].map(value => <option key={value} value={value}>{value} 条</option>)}</select></label>}
    <button disabled={page <= 1} onClick={() => onChange(1)} type="button">首页</button>
    <button disabled={page <= 1} onClick={() => onChange(page-1)} type="button">上一页</button>
    <button disabled={page >= last} onClick={() => onChange(page+1)} type="button">下一页</button>
    <button disabled={page >= last} onClick={() => onChange(last)} type="button">末页</button>
  </nav>;
}
export function AIStatus({state}: {state: string}) {return <span className={'badge ai-' + state}>{aiLabel(state)}</span>;}
