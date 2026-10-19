import type { AlertDetail, Chain, EdgeDetail, Explanation, IncidentDetail, IncidentRow, Overview, Page, SavedExplanation, TimelineItem } from '../types/domain';
export class APIError extends Error { constructor(public status: number, public code: string) { super(code); } }
const safeCode = (value: unknown) => typeof value === 'string' && /^[a-z0-9_:.-]{1,100}$/.test(value) ? value : 'request_failed';
async function request<T>(path: string, signal?: AbortSignal, method = 'GET', explanation = false): Promise<T> {
  let response: Response;
  try { response = await fetch('/api/v1' + path, {method, signal, headers: {Accept: 'application/json'}}); }
  catch (e) { if ((e as Error).name === 'AbortError') throw e; throw new APIError(0, 'network_unavailable'); }
  let body: unknown;
  try { body = await response.json(); } catch { throw new APIError(response.status, 'invalid_response'); }
  if (!response.ok && !(explanation && response.status === 409 && typeof body === 'object' && body !== null && 'report_json' in body && 'generation_status' in body)) {
    throw new APIError(response.status, safeCode((body as {detail?: unknown})?.detail));
  }
  return body as T;
}
const scope = (analysis: string, extra: Record<string, string | number> = {}) => '?' + new URLSearchParams({analysis_id: analysis, ...Object.fromEntries(Object.entries(extra).map(([k, v]) => [k, String(v)]))});
const id = encodeURIComponent;
export const api = {
  overview: (a: string, s?: AbortSignal) => request<Overview>(`/analyses/${id(a)}/overview`, s),
  incidents: (a: string, p: number, kind: string, sort: string, severity: string, s?: AbortSignal) => request<Page<IncidentRow>>(`/analyses/${id(a)}/workbench?page=${p}&page_size=20&kind=${id(kind)}&sort=${id(sort)}${severity ? '&severity=' + id(severity) : ''}`, s),
  incident: (a: string, i: string, s?: AbortSignal) => request<IncidentDetail>(`/incidents/${id(i)}${scope(a)}`, s),
  observations: (a: string, i: string, s?: AbortSignal) => request<{analysis_id: string; incident_id: string; representative_member_count?:number;expanded_member_count?:number;has_dedupe_expansion?:boolean;sources: string[]; fields: {field: string; value: import('../types/domain').Json; alert_ids: string[]; pointers: import('../types/domain').EvidencePointer[]}[]}>(`/incidents/${id(i)}/observations${scope(a)}`, s),
  chain: (a: string, i: string, s?: AbortSignal) => request<{analysis_id: string; chain: Chain; diagnostics_ref: string}>(`/incidents/${id(i)}/chain${scope(a)}`, s),
  timeline: (a: string, i: string, p: number, s?: AbortSignal) => request<Page<TimelineItem>>(`/incidents/${id(i)}/timeline${scope(a, {page: p, page_size: 20})}`, s),
  alert: (a: string, i: string, s?: AbortSignal) => request<AlertDetail>(`/alerts/${id(i)}${scope(a)}`, s),
  edge: (a: string, i: string, s?: AbortSignal) => request<EdgeDetail>(`/edges/${id(i)}${scope(a)}`, s),
  saved: (a: string, i: string, s?: AbortSignal) => request<SavedExplanation>(`/incidents/${id(i)}/explanation${scope(a)}`, s),
  explain: (a: string, i: string, s?: AbortSignal) => request<Explanation>(`/incidents/${id(i)}/explain${scope(a)}`, s, 'POST', true),
};
