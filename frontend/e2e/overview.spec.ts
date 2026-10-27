import {test, expect} from '@playwright/test';

test('态势总览 lands on latest official analysis and chains click into detail', async ({page, request}) => {
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));

  const catalog = await (await request.get('/api/v1/stage-analyses')).json();
  const analysis = await (await request.get('/api/v1/stage-analyses/' + catalog.default_analysis_id)).json();
  const summary = await (await request.get('/api/v1/stage-analyses/' + catalog.default_analysis_id + '/summary')).json();
  const counts = analysis.counts;

  await page.goto('/');

  // Landing heading + default analysis is the official ⑨ reconstruction.
  await expect(page.getByRole('heading', {name: '安全运营态势总览'})).toBeVisible({timeout:60000});
  await expect(page.getByText('正式验收基线 · ⑨ 攻击链重建')).toBeVisible();

  // Metric cards reflect the official counts (not legacy).
  const metric = (label: string) => page.locator('.overview-metric').filter({has: page.locator('.metric-title', {hasText: new RegExp('^'+label+'$')})}).locator('strong');
  await expect(metric('输入告警')).toHaveText(String(counts.input_count));
  await expect(metric('攻击阶段')).toHaveText(String(counts.stage_count));
  await expect(metric('已接受关系')).toHaveText(String(counts.relation_count));
  await expect(metric('攻击链结构')).toHaveText(String(counts.chain_count));
  await expect(metric('有向关系')).toHaveText(String(counts.directed_count ?? 0));
  await expect(metric('无向关系')).toHaveText(String(counts.undirected_count ?? 0));

  // Relation decision donut shows the three decision classes.
  await expect(page.locator('.donut-center')).toHaveText(String(counts.decision_count));
  await expect(page.getByText('有向关系', {exact: true}).first()).toBeVisible();

  // Source distribution shows the six device namespaces.
  await expect(page.locator('.source-row')).toHaveCount(summary.summary.source_namespace.length);

  // The overview is a bounded summary; the full chain index has its own page.
  await expect(page.locator('.recent-chains-table tbody tr')).toHaveCount(Math.min(4,counts.chain_count));
  await expect(page.getByRole('navigation',{name:'功能模块'}).getByRole('link')).toHaveCount(6);
  expect((await page.getByRole('img',{name:'告警时间分布折线图'}).boundingBox())!.y).toBeLessThan(700);

  await page.screenshot({path: '../outputs/overview_checks/01_overview.png', fullPage: true});

  // Click a chain's 查看 → enters stage detail (StageWorkbench).
  await page.locator('.recent-chains-table tbody tr').first().getByRole('button', {name: '查看'}).click();
  await expect(page.getByRole('heading', {name: `${counts.input_count} 条告警分析`})).toBeVisible();
  await expect(page.getByRole('navigation',{name:'功能模块'}).getByRole('link',{name:'攻击链',exact:true})).toHaveAttribute('aria-current','page');
  await page.screenshot({path: '../outputs/overview_checks/02_chain_overview.png', fullPage: true});

  // Return to overview keeps the official default.
  await page.getByRole('navigation',{name:'功能模块'}).getByRole('link',{name:'态势总览'}).click();
  await expect(page.getByRole('heading', {name: '安全运营态势总览'})).toBeVisible();
  await expect(metric('攻击阶段')).toHaveText(String(counts.stage_count));

  expect(errors).toEqual([]);
});

test('态势总览 responsive: 1366 and mobile have no horizontal overflow', async ({page}) => {
  await page.setViewportSize({width: 1366, height: 768});
  await page.goto('/');
  await expect(page.getByRole('heading', {name: '安全运营态势总览'})).toBeVisible({timeout:60000});
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBeTruthy();
  await page.screenshot({path: '../outputs/overview_checks/03_overview_1366.png', fullPage: true});

  await page.setViewportSize({width: 390, height: 844});
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBeTruthy();
  await page.screenshot({path: '../outputs/overview_checks/04_overview_mobile.png', fullPage: true});
});
