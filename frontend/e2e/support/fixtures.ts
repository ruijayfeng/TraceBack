import type {Page, Route} from '@playwright/test';
import fixtureJSON from '../../src/test/fixtures.json' with {type: 'json'};

/**
 * Shared, self-contained API fixture routing for the default Playwright suite
 * (T09/T10/T11).
 *
 * The app under test talks to `/api/v1/**` only. Every one of those endpoints is
 * fulfilled here from `src/test/fixtures.json` (data_kind=synthetic-test-only),
 * so the default suite never needs a real backend, the AIT-ADS dataset, or the
 * network. Tests can override individual payloads (errors, empty pages, saved
 * reports) via the `overrides` argument.
 */

export interface FixtureBundle {
  data_kind: string;
  analysisId: string;
  incidentId: string;
  rows: {
    items: Array<Record<string, unknown> & {
      incident: {incident_id: string; alert_ids: string[]};
      representative_member_count?: number;
      expanded_member_count?: number;
      sources?: string[];
    }>;
    page: number;
    page_size: number;
    total: number;
    analysis_id?: string;
  };
  overview: Record<string, unknown>;
  detail: Record<string, unknown>;
  chain: Record<string, unknown>;
  alert: Record<string, unknown>;
  edge: Record<string, unknown>;
  explanation: Record<string, unknown>;
  saved: Record<string, unknown>;
}

export const fixture = fixtureJSON as unknown as FixtureBundle;

export interface FixtureRouteOverrides {
  overview?: unknown;
  rows?: unknown;
  detail?: unknown;
  chain?: unknown;
  alert?: unknown;
  edge?: unknown;
  explanation?: unknown;
  saved?: unknown;
  observations?: unknown;
  timeline?: unknown;
  /** Return the workbench list payload for a request (lets tests drive filters/pagination). */
  workbench?: (url: URL) => unknown;
}

/** The fixture bundle has no observations payload; derive the deterministic one the UI expects. */
export function fixtureObservations(): Record<string, unknown> {
  const row = fixture.rows.items[0];
  return {
    analysis_id: fixture.analysisId,
    incident_id: fixture.incidentId,
    representative_member_count: row.representative_member_count ?? 2,
    expanded_member_count: row.expanded_member_count ?? 2,
    has_dedupe_expansion: false,
    sources: row.sources ?? ['wazuh'],
    fields: [],
  };
}

/** Intercept and fulfil every `/api/v1/**` call with the synthetic fixture bundle. */
export async function installFixtureRoutes(page: Page, overrides: FixtureRouteOverrides = {}): Promise<void> {
  const bodies = {
    overview: overrides.overview ?? fixture.overview,
    rows: overrides.rows ?? fixture.rows,
    detail: overrides.detail ?? fixture.detail,
    chain: overrides.chain ?? fixture.chain,
    alert: overrides.alert ?? fixture.alert,
    edge: overrides.edge ?? fixture.edge,
    explanation: overrides.explanation ?? fixture.explanation,
    saved: overrides.saved ?? fixture.saved,
    observations: overrides.observations ?? fixtureObservations(),
    timeline: overrides.timeline ?? {items: [], page: 1, page_size: 20, total: 0},
  };

  await page.route('**/api/v1/**', async (route: Route) => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace(/^\/api\/v1/, '');
    const method = route.request().method();
    const fulfil = (body: unknown, status = 200) => route.fulfill({
      status,
      contentType: 'application/json; charset=utf-8',
      body: JSON.stringify(body),
    });

    if (path.endsWith('/overview')) return fulfil(bodies.overview);
    if (path.endsWith('/workbench') || /^\/analyses\/[^/]+\/incidents$/.test(path)) {
      return fulfil(overrides.workbench ? overrides.workbench(url) : bodies.rows);
    }
    if (path.endsWith('/explain')) return fulfil(bodies.explanation);
    if (path.endsWith('/explanation')) return fulfil(bodies.saved);
    if (path.endsWith('/chain')) return fulfil(bodies.chain);
    if (path.endsWith('/observations')) return fulfil(bodies.observations);
    if (path.endsWith('/timeline')) return fulfil(bodies.timeline);
    if (/\/edges\/[^/]+$/.test(path)) return fulfil(bodies.edge);
    if (/\/alerts\/[^/]+$/.test(path)) return fulfil(bodies.alert);
    if (/\/incidents\/[^/]+$/.test(path) && method === 'GET') return fulfil(bodies.detail);
    return fulfil({detail: 'fixture_route_not_mocked'}, 404);
  });
}

/** Open the workbench (dashboard + incident list) at the synthetic analysis id. */
export async function openWorkbench(page: Page): Promise<void> {
  await page.goto(`/?analysis_id=${encodeURIComponent(fixture.analysisId)}`);
}

/** Open the synthetic incident detail page. */
export async function openIncident(page: Page): Promise<void> {
  await page.goto(`/?analysis_id=${encodeURIComponent(fixture.analysisId)}&incident_id=${encodeURIComponent(fixture.incidentId)}`);
}

/**
 * Wait until fonts are ready and two animation frames have passed, so screenshots
 * taken afterwards are stable (T12).
 */
export async function waitForUiSettled(page: Page): Promise<void> {
  await page.evaluate(async () => {
    if (document.fonts?.ready) await document.fonts.ready;
    await new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve())));
  });
}
