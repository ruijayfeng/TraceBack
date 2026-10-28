import AxeBuilder from '@axe-core/playwright';
import {expect, test} from '@playwright/test';
import {installFixtureRoutes, openIncident, openWorkbench} from './support/fixtures';

/**
 * Axe smoke for the framed-sheet redesign. The earlier a11y spec asserts
 * behaviour (dialog semantics, focus, overflow); this one checks the rendered
 * colour/contrast/naming tree on the four core surfaces.
 */
const WCAG = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'best-practice'];

async function expectNoViolations(page: import('@playwright/test').Page, label: string) {
  const results = await new AxeBuilder({page}).withTags(WCAG).analyze();
  const summary = results.violations.map(v => `${v.id} (${v.impact}): ${v.nodes.length} node(s) — ${v.help}`);
  expect(summary, label).toEqual([]);
}

test('workbench renders without axe violations', async ({page}) => {
  await installFixtureRoutes(page);
  await openWorkbench(page);
  await expectNoViolations(page, 'workbench');
});

test('incident detail renders without axe violations', async ({page}) => {
  await installFixtureRoutes(page);
  await openIncident(page);
  await expectNoViolations(page, 'detail');
});

test('evidence drawer renders without axe violations', async ({page}) => {
  await installFixtureRoutes(page);
  await openIncident(page);
  await page.getByRole('button', {name: /查看全部成员证据/}).click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await expectNoViolations(page, 'evidence drawer');
});

test('welcome screen renders without axe violations', async ({page}) => {
  await page.goto('/');
  await expect(page.getByRole('heading', {name: /从碎片告警/})).toBeVisible();
  await expectNoViolations(page, 'welcome');
});
