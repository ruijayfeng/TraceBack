import type { AlertDetail, Chain, EdgeDetail, Explanation, IncidentDetail, IncidentRow, Overview, Page, SavedExplanation, TimelineItem } from '../types/domain';
import type {StageCatalog, StageAnalysis, StageTrace, StageSummary, StageAIResult, StageRun, StageUpload} from '../types/stageAnalysis';
export class APIError extends Error { constructor(public status: number, public code: string) { super(code); } }
const safeCode = (value: unknown) => typeof value === 'string' && /^[a-z0-9_:.-]{1,100}$/.test(value) ? value : 'request_failed';
async function request<T>(path: string, signal?: AbortSignal, method = 'GET', explanation = false, payload?: BodyInit, headers?: HeadersInit): Promise<T> {
  let response: Response;
  try { response = await fetch('/api/v1' + path, {method, signal, body:payload, headers: {Accept: 'application/json', ...headers}}); }
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
function uploadWithPhase(file:File, signal:AbortSignal|undefined, onUploaded:()=>void):Promise<StageUpload> {
  return new Promise((resolve,reject)=>{
    const xhr=new XMLHttpRequest();
    const abort=()=>xhr.abort();
    const cleanup=()=>signal?.removeEventListener('abort',abort);
    xhr.open('POST','/api/v1/stage-runs/uploads');
    xhr.setRequestHeader('Accept','application/json');
    xhr.setRequestHeader('Content-Type','application/octet-stream');
    xhr.setRequestHeader('X-File-Name',encodeURIComponent(file.name));
    xhr.upload.onload=onUploaded;
    xhr.onerror=()=>{cleanup();reject(new APIError(0,'network_unavailable'));};
    xhr.onabort=()=>{cleanup();reject(new DOMException('Upload aborted','AbortError'));};
    xhr.onload=()=>{
      cleanup();let body:StageUpload&{detail?:unknown};
      try{body=JSON.parse(xhr.responseText);}catch{reject(new APIError(xhr.status,'invalid_response'));return;}
      if(xhr.status<200||xhr.status>=300)reject(new APIError(xhr.status,safeCode(body.detail)));else resolve(body);
    };
    if(signal?.aborted){reject(new DOMException('Upload aborted','AbortError'));return;}
    signal?.addEventListener('abort',abort,{once:true});xhr.send(file);
  });
}
export const api = {
  stageUpload: (file:File, s?:AbortSignal, onUploaded?:()=>void) => onUploaded?uploadWithPhase(file,s,onUploaded):request<StageUpload>('/stage-runs/uploads',s,'POST',false,file,{'Content-Type':'application/octet-stream','X-File-Name':encodeURIComponent(file.name)}),
  stageStart: (uploadId:string, s?:AbortSignal) => request<StageRun>('/stage-runs',s,'POST',false,JSON.stringify({upload_id:uploadId}),{'Content-Type':'application/json'}),
  stageRuns: (s?:AbortSignal) => request<{items:StageRun[]}>('/stage-runs',s),
  stageRun: (runId:string, s?:AbortSignal) => request<StageRun>(`/stage-runs/${id(runId)}`,s),
  stageCatalog: (s?: AbortSignal) => request<StageCatalog>('/stage-analyses', s),
  stageAnalysis: (a: string, s?: AbortSignal) => request<StageAnalysis>(`/stage-analyses/${id(a)}`, s),
  stageSummary: (a: string, s?: AbortSignal) => request<StageSummary>(`/stage-analyses/${id(a)}/summary`, s),
  stageTrace: (a: string, subject: string, s?: AbortSignal) => request<StageTrace>(`/stage-analyses/${id(a)}/traces/${id(subject)}`, s),
  stageRaw: (a: string, alert: string, s?: AbortSignal) => request<{raw_alert: unknown}>(`/stage-analyses/${id(a)}/alerts/${id(alert)}`, s),
  stageExplain: (a:string, c:string, s?:AbortSignal) => request<StageAIResult>(`/stage-analyses/${id(a)}/chains/${id(c)}/explain`,s,'POST'),
  stageAISaved: (a:string, c:string, s?:AbortSignal) => request<{result:StageAIResult|null}>(`/stage-analyses/${id(a)}/chains/${id(c)}/explanation`,s),
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
