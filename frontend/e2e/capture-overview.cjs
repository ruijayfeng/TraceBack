// One-off capture of the six required acceptance screenshots.
const {chromium} = require('@playwright/test');
const BASE = process.env.BASE_URL || 'http://127.0.0.1:8000';
const OUT = process.env.OUT_DIR || '../outputs/overview_checks';

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({viewport: {width: 1920, height: 1080}});
  const catalog = await (await fetch(BASE + '/api/v1/stage-analyses')).json();
  const aid = catalog.default_analysis_id;

  // 01 overview
  await page.goto(BASE + '/');
  await page.getByRole('heading', {name: '态势总览'}).waitFor();
  await page.waitForTimeout(600);
  await page.screenshot({path: OUT + '/01_overview.png', fullPage: true});

  // enter chain detail
  await page.locator('.recent-chains-table tbody tr').first().getByRole('button', {name: '查看'}).click();
  await page.getByRole('heading', {name: '125 条告警分析'}).waitFor();
  await page.waitForTimeout(600);
  await page.screenshot({path: OUT + '/03_chain_detail.png', fullPage: true});

  // 04 stage evidence
  await page.getByRole('button', {name: '查看阶段证据', exact: true}).first().click();
  const drawer = page.getByRole('dialog');
  await drawer.getByRole('heading', {name: '证据追溯', exact: true}).waitFor();
  await page.waitForTimeout(400);
  await page.screenshot({path: OUT + '/04_stage_evidence.png'});

  // 06 raw alert
  await drawer.getByRole('button', {name: '查看原始告警', exact: true}).first().click();
  await drawer.locator('.json-view pre').first().waitFor();
  await page.screenshot({path: OUT + '/06_raw_alert.png'});
  await page.keyboard.press('Escape');

  // 05 relation evidence
  await page.getByRole('button', {name: '查看关系证据', exact: true}).first().scrollIntoViewIfNeeded();
  await page.getByRole('button', {name: '查看关系证据', exact: true}).first().click();
  await drawer.getByRole('heading', {name: '证据追溯', exact: true}).waitFor();
  await page.waitForTimeout(400);
  await page.screenshot({path: OUT + '/05_relation_evidence.png'});

  // 02 chain overview (back on the landing page, chain section focused)
  await page.goto(BASE + '/');
  await page.getByRole('heading', {name: '态势总览'}).waitFor();
  await page.locator('.chain-selector').scrollIntoViewIfNeeded();
  await page.waitForTimeout(400);
  await page.screenshot({path: OUT + '/02_chain_overview.png'});

  await browser.close();
  console.log('screenshots done');
})().catch(e => { console.error(e); process.exit(1); });
