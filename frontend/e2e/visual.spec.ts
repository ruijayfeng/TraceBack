import {test, expect, type Page} from '@playwright/test';
import {existsSync, mkdirSync} from 'node:fs';
import path from 'node:path';
import {fixture, installFixtureRoutes, openIncident, openWorkbench, waitForUiSettled} from './support/fixtures';

/**
 * T12 — deterministic visual baselines.
 *
 * For each of the four product widths (1440/1024/768/390) captures:
 *   workbench (dashboard + list, fullPage)
 *   detail    (incident detail, fullPage ~6k px; acceptable per plan)
 *   ai        (AI report area, viewport at its top)
 *   drawer    (evidence drawer open, viewport)
 *
 * Output: <design-libs>/baseline/visual/<width>/<name>.png
 * Determinism: synthetic fixture only (no backend / no real dataset), fixed
 * timestamps inside the fixture, `reducedMotion: 'reduce'` (playwright.config.ts),
 * `animations: 'disabled'` on every screenshot, fonts ready + two frames settled.
 *
 * Generate/refresh with: npm run test:e2e:visual (or the whole default suite).
 * Override the output root with TRACEBACK_VISUAL_BASELINE_DIR.
 */

function resolveVisualBaselineDir(): string {
  if (process.env.TRACEBACK_VISUAL_BASELINE_DIR) return path.resolve(process.env.TRACEBACK_VISUAL_BASELINE_DIR);
  const roots = [
    path.resolve(process.cwd(), '../../design-libs'), // cwd = frontend/
    path.resolve(process.cwd(), '../design-libs'), // cwd = TraceBack/
    path.resolve(process.cwd(), 'design-libs'), // cwd = ui/
    '/Users/softbook/dev/ui/design-libs', // documented absolute fallback
  ];
  const root = roots.find(candidate => existsSync(candidate));
  if (!root) throw new Error(`Cannot locate design-libs; tried: ${roots.join(', ')}`);
  return path.join(root, 'baseline', 'visual');
}

const visualDir = resolveVisualBaselineDir();

async function capture(page: Page, width: number, name: string, options: {fullPage?: boolean} = {}): Promise<void> {
  const dir = path.join(visualDir, String(width));
  mkdirSync(dir, {recursive: true});
  await waitForUiSettled(page);
  await page.screenshot({path: path.join(dir, `${name}.png`), animations: 'disabled', caret: 'hide', ...options});
}

const VIEWPORTS = [
  {width: 1440, height: 900},
  {width: 1024, height: 768},
  {width: 768, height: 1024},
  {width: 390, height: 844},
] as const;

for (const viewport of VIEWPORTS) {
  test.describe(`visual baseline ${viewport.width}px`, () => {
    test.use({viewport});

    test(`captures workbench / detail / AI report / evidence drawer at ${viewport.width}px`, async ({page}) => {
      await installFixtureRoutes(page);

      // 1. Workbench: dashboard + incident list.
      await openWorkbench(page);
      await expect(page.getByRole('heading', {name: '安全事件工作台'})).toBeVisible();
      await expect(page.getByRole('heading', {name: '安全事件列表'})).toBeVisible();
      await expect(page.getByRole('button', {name: '查看详情 →'})).toBeVisible();
      await capture(page, viewport.width, 'workbench', {fullPage: true});

      // 2. Incident detail (includes the full evidence/AI sections).
      await openIncident(page);
      // T51: detail h1 is incident.summary; incident kind is a badge below it.
      await expect(page.getByRole('heading', {name: String((fixture.detail as any).incident.summary)})).toBeVisible();
      await expect(page.getByText('关联聚合事件', {exact: true}).first()).toBeVisible();
      await expect(page.getByRole('heading', {name: '安全事件摘要'})).toBeVisible();
      await capture(page, viewport.width, 'detail', {fullPage: true});

      // 3. AI report area, scrolled to its top.
      const aiArea = page.locator('.ai-area');
      await aiArea.evaluate(element => element.scrollIntoView({block: 'start'}));
      await expect(page.getByRole('heading', {name: 'AI 研判报告'})).toBeVisible();
      await capture(page, viewport.width, 'ai');

      // 4. Evidence dialog open (T68: Base UI Sheet; side sheet on desktop, bottom sheet on phones).
      await openIncident(page);
      await page.getByRole('button', {name: /查看全部成员证据/}).click();
      const dialog = page.getByRole('dialog');
      await expect(dialog).toBeVisible();
      // Let the Sheet's enter transition finish (Base UI removes data-starting-style after mount).
      await page.waitForFunction(() => {
        const popup = document.querySelector('[data-slot="sheet-popup"]');
        return Boolean(popup) && !popup!.hasAttribute('data-starting-style');
      });
      await expect(dialog.getByText('相关字段')).toBeVisible();
      await capture(page, viewport.width, 'drawer');
    });
  });
}
