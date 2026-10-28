import {test, expect} from '@playwright/test';
import {existsSync, readFileSync} from 'node:fs';
import path from 'node:path';
import {fixture, installFixtureRoutes, openIncident} from './support/fixtures';

/**
 * Workbench e2e suite.
 *
 * - Default (CI) tests are self-contained: Vite on 127.0.0.1:4173 (webServer) +
 *   `/api/v1/**` fulfilled from `src/test/fixtures.json` (data_kind=synthetic-test-only).
 * - Tests tagged `@real` keep the original AIT-ADS assertions for future use, but
 *   are skipped unless BOTH `TRACEBACK_REAL_DATA=1` AND the real dataset file
 *   exist at runtime. The file is read with `fs` inside the test (never a static
 *   `import`), so Playwright collection does not fail when it is absent.
 *
 * Real run:
 *   TRACEBACK_REAL_DATA=1 TRACEBACK_WEB_URL=http://127.0.0.1:8000 npm run test:e2e:real
 */

const REAL_DATA_REL = 'outputs/task09_1/real-expanded-incidents.json';

/** Locate the optional real dataset without importing it (T09). */
function findRealDataFile(): string | null {
  const candidates = [
    process.env.TRACEBACK_REAL_DATA_FILE,
    path.resolve(process.cwd(), '..', REAL_DATA_REL), // cwd = frontend/
    path.resolve(process.cwd(), REAL_DATA_REL), // cwd = TraceBack/
    path.resolve(process.cwd(), '..', '..', REAL_DATA_REL), // cwd = frontend/e2e/
  ].filter((value): value is string => Boolean(value));
  for (const candidate of candidates) if (existsSync(candidate)) return candidate;
  return null;
}

const realDataFile = findRealDataFile();
const realEnabled = process.env.TRACEBACK_REAL_DATA === '1' && realDataFile !== null;
const realId = process.env.TRACEBACK_ANALYSIS_ID || 'ana_c0898b8ba20bbc07ae2c661dc27e9435b355b110c8ffee4324fce9763132d6ff';

/** Read the real expansion list at runtime; only called by @real tests. */
function loadExpandedIncidents(): unknown[][] {
  if (!realDataFile) throw new Error(`real dataset missing: ${REAL_DATA_REL}`);
  const parsed: unknown = JSON.parse(readFileSync(realDataFile, 'utf8'));
  if (!Array.isArray(parsed)) throw new Error(`unexpected real dataset shape in ${realDataFile}`);
  return parsed as unknown[][];
}

test.describe('synthetic fixture workbench (self-contained)', () => {
  test('dashboard, list filters and server pagination work without any backend', async ({page}) => {
    const requests: string[] = [];
    page.on('request', request => requests.push(request.url()));
    await installFixtureRoutes(page, {
      workbench: url => ({
        // total=45 so the list offers a next page, mirroring the real 2,276-page UX.
        ...fixture.rows,
        page: Number(url.searchParams.get('page') ?? 1),
        total: url.searchParams.get('kind') === 'multi_alert' ? 0 : 45,
        items: url.searchParams.get('kind') === 'multi_alert' ? [] : fixture.rows.items,
      }),
    });
    await page.goto(`/?analysis_id=${fixture.analysisId}`);

    // Dashboard
    await expect(page.getByRole('heading', {name: '安全事件工作台'})).toBeVisible();
    await expect(page.locator('.metric').filter({hasText: '安全事件'}).getByText('1', {exact: true})).toBeVisible();
    await expect(page.getByText('去重诊断')).toBeVisible();

    // Incident list
    await expect(page.getByRole('heading', {name: '安全事件列表'})).toBeVisible();
    await expect(page.getByRole('button', {name: '查看详情 →'})).toHaveCount(1);
    await expect(page.getByText('45 条 · 第 1 / 3 页')).toBeVisible();

    // Filter → empty state, then back
    await page.getByLabel('事件类型').selectOption('multi_alert');
    await expect(page.getByText('当前筛选下没有安全事件。')).toBeVisible();
    await page.getByLabel('事件类型').selectOption('all');
    await expect(page.getByText('45 条 · 第 1 / 3 页')).toBeVisible();

    // Pagination is reflected in the URL and survives a reload.
    await page.getByRole('button', {name: '下一页'}).click();
    await expect(page).toHaveURL(/page=2/);
    await expect(page.getByText('45 条 · 第 2 / 3 页')).toBeVisible();
    await page.reload();
    await expect(page.getByText('45 条 · 第 2 / 3 页')).toBeVisible();

    // Drill into the incident detail page through the SPA.
    await page.getByRole('button', {name: '查看详情 →'}).click();
    // T51: detail h1 is incident.summary; the incident kind ("关联聚合事件") is a badge below it.
    await expect(page.getByRole('heading', {name: String((fixture.detail as any).incident.summary)})).toBeVisible();
    await expect(page.getByText('关联聚合事件', {exact: true}).first()).toBeVisible();
    await expect(page.getByRole('heading', {name: '攻击链 · 已观测步骤与传播'})).toBeVisible();

    // Self-contained guarantee: nothing reaches the legacy real backend (:8000) or the internet.
    expect(requests.filter(url => url.includes(':8000') || url.includes('/evaluation/') || url.includes('labels.csv'))).toEqual([]);
  });

  test('accepted synthetic two-node graph → exact direction → edge evidence (test fixture only)', async ({page}) => {
    await installFixtureRoutes(page);
    await openIncident(page);
    await expect(page.getByRole('heading', {name: String((fixture.detail as any).incident.summary)})).toBeVisible();
    await expect(page.getByText('关联聚合事件', {exact: true}).first()).toBeVisible();
    const edge = page.locator('g.graph-edge');
    await expect(edge).toHaveAttribute('data-source', String((fixture.edge as any).edge.source_node_id));
    await expect(edge).toHaveAttribute('data-target', String((fixture.edge as any).edge.target_node_id));
    // Keyboard selection via the focusable `g.graph-edge` group; a bbox-centre pointer
    // click can land in the empty space beside the curved edge path.
    await page.getByRole('button', {name: /选择边/}).press('Enter');
    await expect(page.getByText('实际支撑告警对')).toBeVisible();
    await page.getByText('查看边证据与字段指针').click();
    await expect(page.getByText('相关字段')).toBeVisible();
    await page.getByRole('button', {name: '关闭证据', exact: true}).click();
    await page.screenshot({path: '../outputs/task09_1/browser/synthetic-edge.png', fullPage: true});
  });
});

test.describe('真实 AIT-ADS 数据集 @real (env + file gated)', () => {
  test.skip(!realEnabled, [
    '需要 TRACEBACK_REAL_DATA=1 且真实数据集文件存在（不是合成 fixture，也没有伪造文件）。',
    `候选路径（cwd=${process.cwd()}）: ${process.env.TRACEBACK_REAL_DATA_FILE || path.resolve(process.cwd(), '..', REAL_DATA_REL)} 或 ${path.resolve(process.cwd(), REAL_DATA_REL)}`,
  ].join(' '));

  test('real Analysis → singleton → node → Evidence → unavailable AI → persisted report → refresh', async ({page, request}) => {
    const errors: string[] = [];
    page.on('pageerror', e => errors.push(e.message));
    const requests: string[] = [];
    page.on('request', r => requests.push(r.url()));
    await page.goto('/?analysis_id=' + realId);
    await expect(page.getByRole('heading', {name: '安全事件工作台'})).toBeVisible();
    await expect(page.locator('.metric').filter({hasText: '安全事件'}).getByText('45,501', {exact: true})).toBeVisible();
    await expect(page.getByRole('heading', {name: '关联评分诊断'})).toBeVisible();
    await expect(page.getByText('826,313', {exact: true})).toBeVisible();
    await expect(page.getByText(/0.547562658/)).toBeVisible();
    await expect(page.getByText(/已核验候选剪枝不会遗漏/)).toBeVisible();
    await page.screenshot({path: '../outputs/task09_1/browser/dashboard.png', fullPage: true});
    await page.screenshot({path: '../outputs/task09_1/browser/dashboard-viewport.png'});
    await page.getByLabel('事件类型').selectOption('singleton');
    await expect(page.getByText('45,501 条', {exact: false})).toBeVisible();
    await page.getByRole('button', {name: '查看详情 →'}).first().click();
    await expect(page.getByRole('heading', {name: '单代表告警事件'})).toBeVisible();
    await expect(page.getByText(/未重构出已验证的传播边/)).toBeVisible();
    await page.getByRole('button', {name: /选择节点/}).click();
    await expect(page.getByText('为什么存在这个节点')).toBeVisible();
    await page.getByRole('button', {name: /查看节点证据/}).click();
    await expect(page.getByText('相关字段')).toBeVisible();
    await page.getByText('原始设备告警').click();
    await expect(page.locator('.raw-evidence pre').first()).toBeVisible();
    await page.screenshot({path: '../outputs/task09_1/browser/evidence.png', fullPage: true});
    await page.getByRole('button', {name: '关闭证据', exact: true}).click();
    const explain = page.getByRole('button', {name: /请求 AI 研判/});
    await expect(explain).toBeEnabled();
    await explain.click();
    await expect(page.getByText('AI 不可用', {exact: true})).toBeVisible();
    await expect(page.getByRole('heading', {name: '安全事件摘要'})).toBeVisible();
    await expect(page.getByText('没有通过本地目录校验的 ATT&CK 技术。')).toBeVisible();
    await page.getByRole('button', {name: /查看陈述证据/}).first().click();
    await expect(page.getByText('绑定证据指针')).toBeVisible();
    await page.getByRole('button', {name: '关闭证据', exact: true}).click();
    await page.screenshot({path: '../outputs/task09_1/browser/incident.png', fullPage: true});
    const url = page.url();
    await page.reload();
    await expect(page.getByText('已保存报告')).toBeVisible();
    expect(page.url()).toBe(url);
    const jsonDownload = page.waitForEvent('download');
    await page.getByRole('button', {name: '导出 JSON'}).click();
    expect((await jsonDownload).suggestedFilename()).toMatch(/^inc_.*\.json$/);
    expect(errors).toEqual([]);
    expect(requests.every(url => !url.includes('labels.csv') && !url.includes('/evaluation/') && !url.includes('api.openai.com'))).toBeTruthy();
    const overview = await request.get(`/api/v1/analyses/${realId}/overview`);
    expect(overview.ok()).toBeTruthy();
    expect((await overview.json()).counts.chain_edge_count).toBe(0);
  });

  test('real global multi-alert and zero-chain filters, stable pagination and mobile layout', async ({page}) => {
    await page.goto('/?analysis_id=' + realId);
    await expect(page.getByRole('heading', {name: '安全事件工作台'})).toBeVisible();
    await page.getByLabel('事件类型').selectOption('multi_alert');
    await expect(page.getByText('0 条 · 第 1 / 1 页')).toBeVisible();
    await page.getByLabel('事件类型').selectOption('has_chain');
    await expect(page.getByText('当前筛选下没有安全事件。')).toBeVisible();
    await page.getByLabel('事件类型').selectOption('all');
    await expect(page.getByRole('button', {name: '下一页'})).toBeEnabled();
    await page.getByRole('button', {name: '下一页'}).click();
    await expect(page).toHaveURL(/page=2/);
    await page.reload();
    await expect(page.getByText(/第 2 \/ 2276 页/)).toBeVisible();
    await page.setViewportSize({width: 390, height: 844});
    await page.screenshot({path: '../outputs/task09_1/browser/mobile.png', fullPage: true});
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBeTruthy();
  });

  test('real dedupe expansion is one representative with two canonical alerts', async ({page, request}) => {
    const expanded = loadExpandedIncidents();
    const overview = await (await request.get(`/api/v1/analyses/${realId}/overview`)).json();
    expect(overview.counts.representative_singleton_incident_count).toBe(45501);
    expect(overview.counts.correlated_multi_alert_incident_count).toBe(0);
    expect(overview.counts.incidents_with_dedupe_expansion_count).toBe(9);
    const incidentId = String(expanded[0][0]);
    const observations = await (await request.get(`/api/v1/incidents/${incidentId}/observations?analysis_id=${realId}`)).json();
    expect(observations.representative_member_count).toBe(1);
    expect(observations.expanded_member_count).toBe(2);
    await page.goto(`/?analysis_id=${realId}&incident_id=${incidentId}`);
    await expect(page.getByRole('heading', {name: '单代表告警事件'})).toBeVisible();
    await expect(page.getByText('1 去重代表 · 2 展开告警 · 1 节点 · 0 边')).toBeVisible();
    await expect(page.locator('g.graph-node')).toHaveCount(1);
    await expect(page.locator('g.graph-edge')).toHaveCount(0);
    await page.screenshot({path: '../outputs/task09_1/browser/real-dedupe-expanded.png', fullPage: true});
  });
});
