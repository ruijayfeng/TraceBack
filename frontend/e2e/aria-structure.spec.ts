import {test, expect} from '@playwright/test';
import {installFixtureRoutes, openIncident, openWorkbench} from './support/fixtures';

/**
 * F24 — accessible-name/structure regression for screen-reader paths.
 * These assert the ARIA tree text exposed by Playwright (equivalent to what a
 * VoiceOver/NVDA user navigates) without brittle full snapshots.
 */
test('workbench list exposes table, buttons and pagination names', async ({page}) => {
  await installFixtureRoutes(page);
  await openWorkbench(page);
  await expect(page.getByRole('table')).toBeVisible();
  const tree = await page.locator('main').ariaSnapshot();
  expect(tree).toContain('heading "安全事件列表"');
  expect(tree).toContain('button "查看详情 →"');
  expect(tree).toContain('button "下一页"');
  expect(tree).toContain('搜索当前页');
});

test('detail page exposes headings, tabs and attack-chain buttons', async ({page}) => {
  await installFixtureRoutes(page);
  await openIncident(page);
  const tree = await page.locator('main').ariaSnapshot();
  expect(tree).toContain('navigation "页内导航"');
  expect(tree).toContain('heading "攻击链 · 已观测步骤与传播"');
  expect(tree).toContain('选择节点');
  expect(tree).toContain('heading "AI 研判报告"');
});

test('evidence sheet exposes dialog, title and close affordance', async ({page}) => {
  await installFixtureRoutes(page);
  await openIncident(page);
  await page.getByRole('button', {name: /查看全部成员证据/}).click();
  await expect(page.getByRole('dialog')).toBeVisible();
  const tree = await page.getByRole('dialog').ariaSnapshot();
  expect(tree).toContain('dialog');
  expect(tree).toContain('button "关闭证据"');
  expect(tree).toContain('listbox "支撑告警"');
});
