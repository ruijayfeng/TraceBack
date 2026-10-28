export interface ListFilters {
  page: number;
  pageSize: number;
  kind: string;
  sort: string;
  severity: string;
  q: string;
  entity: string;
  /** RFC3339 UTC bounds; empty means unbounded. */
  startTime: string;
  endTime: string;
}

export interface Route {
  analysisId: string;
  incidentId: string;
  filters: ListFilters;
  /** Deep links: node/edge selection, evidence alert and timeline page. */
  nodeId: string;
  edgeId: string;
  evidenceId: string;
  timelinePage: number;
}

export const DEFAULT_FILTERS: ListFilters = {page: 1, pageSize: 20, kind: 'all', sort: 'time', severity: '', q: '', entity: '', startTime: '', endTime: ''};
export const PAGE_SIZE_VALUES = [20, 50, 100] as const;
export const KIND_VALUES = ['all', 'singleton', 'multi_alert', 'has_chain', 'ai_explained', 'ai_pending'] as const;
export const SORT_VALUES = ['time', 'alert_count', 'node_count'] as const;
export const SEVERITY_VALUES = ['', 'critical', 'high', 'medium', 'low', 'informational', 'unknown'] as const;
export const MAX_PAGE = 100000;
export const MAX_QUERY_LENGTH = 120;

function oneOf<T extends string>(values: readonly T[], fallback: T, raw: string | null): T {
  return raw && (values as readonly string[]).includes(raw) ? (raw as T) : fallback;
}

const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const timeBound = (raw: string | null): string => raw && RFC3339.test(raw) ? raw : '';

const positiveInt = (raw: string | null, fallback: number): number => {
  if (!raw || !/^\d{1,9}$/.test(raw)) return fallback;
  return Math.min(Math.max(Number(raw), 1), MAX_PAGE);
};

/** Parse + clamp untrusted URL state; invalid values fall back instead of failing the page. */
export function readLocation(search: string = window.location.search): Route {
  const params = new URLSearchParams(search);
  const rawSize = Number(params.get('page_size'));
  const pageSize = (PAGE_SIZE_VALUES as readonly number[]).includes(rawSize) ? rawSize : DEFAULT_FILTERS.pageSize;
  const nodeId = params.get('node_id') ?? '';
  const edgeId = params.get('edge_id') ?? '';
  return {
    analysisId: params.get('analysis_id') ?? '',
    incidentId: params.get('incident_id') ?? '',
    filters: {
      page: positiveInt(params.get('page'), 1),
      pageSize,
      kind: oneOf(KIND_VALUES, 'all', params.get('kind')),
      sort: oneOf(SORT_VALUES, 'time', params.get('sort')),
      severity: oneOf(SEVERITY_VALUES, '', params.get('severity')),
      q: (params.get('q') ?? '').trim().slice(0, MAX_QUERY_LENGTH),
      entity: (params.get('entity') ?? '').trim().slice(0, MAX_QUERY_LENGTH),
      startTime: timeBound(params.get('start_time')),
      endTime: timeBound(params.get('end_time')),
    },
    nodeId: nodeId.startsWith('nod_') ? nodeId : '',
    edgeId: edgeId.startsWith('che_') ? edgeId : '',
    evidenceId: (params.get('evidence') ?? '').slice(0, 200),
    timelinePage: positiveInt(params.get('timeline_page'), 1),
  };
}

/** Parse a full href (path + query) into a route. */
export function readHref(href: string): Route {
  return readLocation(new URL(href, window.location.origin).search);
}

export function routeHref(route: Route): string {
  const params = new URLSearchParams();
  if (route.analysisId) params.set('analysis_id', route.analysisId);
  if (route.incidentId) params.set('incident_id', route.incidentId);
  const {page, pageSize, kind, sort, severity, q, entity, startTime, endTime} = route.filters;
  if (page !== DEFAULT_FILTERS.page) params.set('page', String(page));
  if (pageSize !== DEFAULT_FILTERS.pageSize) params.set('page_size', String(pageSize));
  if (kind !== DEFAULT_FILTERS.kind) params.set('kind', kind);
  if (sort !== DEFAULT_FILTERS.sort) params.set('sort', sort);
  if (severity) params.set('severity', severity);
  if (q) params.set('q', q);
  if (entity) params.set('entity', entity);
  if (startTime) params.set('start_time', startTime);
  if (endTime) params.set('end_time', endTime);
  if (route.nodeId) params.set('node_id', route.nodeId);
  if (route.edgeId) params.set('edge_id', route.edgeId);
  if (route.evidenceId) params.set('evidence', route.evidenceId);
  if (route.timelinePage !== 1) params.set('timeline_page', String(route.timelinePage));
  const query = params.toString();
  return window.location.pathname + (query ? '?' + query : '');
}

export function routeTitle(route: Route): string {
  if (route.incidentId) return '安全事件详情 · TraceBack';
  if (route.analysisId) return '安全事件工作台 · TraceBack';
  return 'TraceBack · 安全事件研判工作台';
}
