import {aiLabel} from '../lib/displayLabels';
import {useState, type ReactNode} from 'react';
export const shortId = (value: string) => value.length > 22 ? value.slice(0, 12) + '…' + value.slice(-6) : value;
export function StableId({value}: {value: string}) {return <code title={value}>{shortId(value)}</code>;}
export function Time({value}: {value: string}) {return <time dateTime={value} title={value}>{value.replace('T', ' ').replace('Z', ' UTC')}</time>;}
export function Notice({kind = 'empty', children}: {kind?: 'empty' | 'loading' | 'error' | 'info'; children: ReactNode}) {
  return <div className={'notice ' + kind} role={kind === 'error' ? 'alert' : 'status'}>{children}</div>;
}
export function Section({title, hint, children}: {title: string; hint?: string; children: ReactNode}) {return <section className="panel"><div className="section-heading"><h2>{title}</h2>{hint && <span className="muted">{hint}</span>}</div>{children}</section>;}
export function JsonView({value, title = '原始内容'}: {value: unknown; title?: string}) {
  const [expanded, setExpanded] = useState(false);
  const text = JSON.stringify(value, null, 2) ?? '';
  return <div className="json-view"><pre>{text.slice(0, 2400)}{text.length > 2400 ? '\n… 已折叠' : ''}</pre>{text.length > 2400 && <details onToggle={e => setExpanded(e.currentTarget.open)}><summary>展开 {title}（{text.length.toLocaleString()} 字符）</summary>{expanded && <pre>{text}</pre>}</details>}</div>;
}
export function Pager({page, total, onChange, size = 20}: {page: number; total: number; onChange: (p: number) => void; size?: number}) {
  const last = Math.max(1, Math.ceil(total / size));
  return <nav className="pager" aria-label="分页"><span>{total.toLocaleString()} 条 · 第 {page} / {last} 页</span><button disabled={page <= 1} onClick={() => onChange(page-1)}>上一页</button><button disabled={page >= last} onClick={() => onChange(page+1)}>下一页</button></nav>;
}
export function AIStatus({state}: {state: string}) {return <span className={'badge ai-' + state}>{aiLabel(state)}</span>;}
