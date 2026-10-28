import {describe,it,expect} from 'vitest';
import {DEFAULT_FILTERS,readLocation,routeHref} from '../lib/route';

describe('URL filter schema', () => {
  it('falls back and clamps untrusted URL values', () => {
    const route = readLocation('?analysis_id=ana_x&page=-3&page_size=33&kind=not-a-kind&sort=weird&severity=extreme&q=' + '长'.repeat(200));
    expect(route.filters.page).toBe(1);
    expect(route.filters.pageSize).toBe(DEFAULT_FILTERS.pageSize);
    expect(route.filters.kind).toBe(DEFAULT_FILTERS.kind);
    expect(route.filters.sort).toBe(DEFAULT_FILTERS.sort);
    expect(route.filters.severity).toBe(DEFAULT_FILTERS.severity);
    expect(route.filters.q.length).toBe(120);
  });
  it('keeps valid filters and omits defaults from the href', () => {
    const route = readLocation('?analysis_id=ana_x&page=3&page_size=50&kind=has_chain&sort=alert_count&severity=high&q=host');
    expect(route.filters).toEqual({page:3,pageSize:50,kind:'has_chain',sort:'alert_count',severity:'high',q:'host',entity:'',startTime:'',endTime:''});
    const href = routeHref(route);
    expect(href).toContain('page=3');
    expect(href).toContain('page_size=50');
    expect(href).toContain('kind=has_chain');
    expect(href).toContain('q=host');
    const plain = routeHref({analysisId:'ana_x',incidentId:'',filters:DEFAULT_FILTERS,nodeId:'',edgeId:'',evidenceId:'',timelinePage:1});
    expect(plain).not.toContain('page=');
    expect(plain).not.toContain('page_size=');
  });
});
