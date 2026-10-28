import {test, expect} from '@playwright/test';
import {fixture, installFixtureRoutes} from './support/fixtures';

/**
 * Moved from `src/__tests__/demo.browser.spec.ts` (T10): it is a Playwright test,
 * so it lives in `e2e/` and runs in the default self-contained suite. All API
 * traffic is intercepted from `src/test/fixtures.json`; no backend is involved.
 */

test('backend unavailable and missing/damaged snapshot have finite visible errors', async ({page}) => {
  for (const state of ['network_unavailable', 'analysis_not_found', 'snapshot_integrity_error']) {
    await page.route('**/api/v1/**', async route => {
      if (state === 'network_unavailable') await route.abort('connectionrefused');
      else await route.fulfill({status: state === 'analysis_not_found' ? 404 : 409, json: {detail: state}});
    });
    await page.goto('/?analysis_id=ana_' + '0'.repeat(64));
    await expect(page.getByRole('alert').first()).toContainText(state);
    await expect(page.getByText('正在读取安全事件列表…')).not.toBeVisible();
    await page.unroute('**/api/v1/**');
  }
});

test('Synthetic Fixture / Functional Demonstration: exact direction, edge and ATT&CK Evidence', async ({page}) => {
  const data = structuredClone(fixture);
  // A UI-only validated mapping fixture exercises navigation, not real ATT&CK discovery.
  const report = data.saved.result!.report_json!;
  const claim = {...report.claims[0], claim_id: 'synthetic-map', kind: 'attack_mapping', text: 'Synthetic mapping navigation only'};
  report.claims.push(claim as typeof report.claims[number]);
  const technique = {claim_id: claim.claim_id, technique_id: 'T1059', technique_name: 'Command and Scripting Interpreter', tactic: 'execution',
    reason: 'Synthetic functional navigation', catalog_version: 'synthetic-test-only', mapping_status: 'validated',
    node_refs: [data.chain.chain.nodes[0].node_id], edge_refs: [], alert_refs: [data.alert.alert.alert_id],
    evidence_refs: report.summary[0].evidence_refs};
  report.attack_techniques.push(technique as typeof report.attack_techniques[number]);
  await page.addInitScript(() => {
    addEventListener('DOMContentLoaded', () => {
      const banner = document.createElement('aside');
      banner.textContent = 'Synthetic Fixture / Functional Demonstration — 非 AIT-ADS 真实攻击链';
      banner.setAttribute('data-testid', 'synthetic-banner');
      banner.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:9999;padding:10px;background:#fff3c4;color:#563700;text-align:center;font-weight:bold';
      document.body.append(banner);
    });
  });
  const requests: string[] = [];
  page.on('request', r => requests.push(r.url()));
  await installFixtureRoutes(page, {
    overview: data.overview,
    rows: data.rows,
    detail: data.detail,
    chain: data.chain,
    alert: data.alert,
    edge: data.edge,
    explanation: data.explanation,
    saved: data.saved,
  });
  await page.goto(`/?analysis_id=${data.analysisId}&incident_id=${data.incidentId}`);
  await expect(page.getByTestId('synthetic-banner')).toBeVisible();
  const edge = page.locator('g.graph-edge');
  await expect(edge).toHaveAttribute('data-source', data.edge.edge.source_node_id);
  await expect(edge).toHaveAttribute('data-target', data.edge.edge.target_node_id);
  // Select the edge through its focusable graph group (keyboard Enter is deterministic;
  // Playwright's bbox-centre click can miss the curved edge-hit path on the SVG).
  await page.getByRole('button', {name: /选择边/}).press('Enter');
  await expect(page.getByText('实际支撑告警对')).toBeVisible();
  await page.getByRole('heading', {name: '攻击链 · 已观测步骤与传播'}).scrollIntoViewIfNeeded();
  await page.screenshot({path: '../outputs/task09_1/browser/synthetic-chain-viewport.png'});
  await page.getByText('查看边证据与字段指针').click();
  await expect(page.getByText('相关字段')).toBeVisible();
  await page.getByRole('button', {name: '关闭证据', exact: true}).click();
  const mapping = page.getByText(/T1059 ·/).locator('..');
  await expect(mapping).toBeVisible();
  await mapping.getByRole('button', {name: /查看陈述证据/}).click();
  await expect(page.getByText('绑定证据指针')).toBeVisible();
  await page.screenshot({path: '../outputs/task09_1/browser/synthetic-mapping-viewport.png'});
  await page.screenshot({path: '../outputs/task09_1/browser/synthetic-showcase.png', fullPage: true});
  expect(requests.every(u => !u.includes('labels.csv') && !u.includes('/evaluation/'))).toBeTruthy();
});
