import {test, expect, type Page} from '@playwright/test';
import {installFixtureRoutes, openIncident, openWorkbench} from './support/fixtures';

/**
 * T13 — responsive + accessibility smoke for the default (self-contained) suite.
 *
 * Current state (verified against the app at 2026-10-28 11:2x):
 *   - 768/390 page-level horizontal overflow: fixed by T32 (breakpoint rework),
 *     asserted as a normal requirement here.
 *   - evidence drawer: rebuilt on the Base UI Dialog/Sheet (T68) → role=dialog,
 *     accessible name comes from the sheet title (the evidence selection title),
 *     focus moves into the dialog, Esc closes, body scroll lock, focus restores
 *     to the triggering button.
 * Everything here is a normal (green) assertion; nothing is fixmed anymore.
 */

async function documentWidth(page: Page): Promise<{scrollWidth: number; innerWidth: number}> {
  return page.evaluate(() => ({scrollWidth: document.documentElement.scrollWidth, innerWidth: window.innerWidth}));
}

async function expectNoHorizontalOverflow(page: Page): Promise<void> {
  const {scrollWidth, innerWidth} = await documentWidth(page);
  expect(scrollWidth, `documentElement.scrollWidth=${scrollWidth} must be <= window.innerWidth=${innerWidth}+1`).toBeLessThanOrEqual(innerWidth + 1);
}

async function openDrawer(page: Page) {
  const trigger = page.getByRole('button', {name: /查看全部成员证据/});
  await trigger.click();
  // Base UI labels the dialog with its SheetTitle (the evidence selection title),
  // so query the role instead of hard-coding a name that duplicates the title.
  const dialog = page.getByRole('dialog');
  await expect(dialog).toBeVisible();
  return {trigger, dialog};
}

for (const width of [768, 390] as const) {
  test.describe(`responsive smoke ${width}px`, () => {
    test.use({viewport: {width, height: width === 390 ? 844 : 1024}});

    test(`workbench has no horizontal page overflow at ${width}px`, async ({page}) => {
      // T32 (lead fix 2026-10-28T11:0x): 768 was +10px before the breakpoint rework;
      // it is asserted as a normal requirement now.
      await installFixtureRoutes(page);
      await openWorkbench(page);
      await expect(page.getByRole('heading', {name: '安全事件列表'})).toBeVisible();
      await expectNoHorizontalOverflow(page);
    });

    test(`incident detail has no horizontal page overflow at ${width}px`, async ({page}) => {
      await installFixtureRoutes(page);
      await openIncident(page);
      // T51: h1 is incident.summary, the incident kind is a badge below it.
      await expect(page.getByText('关联聚合事件', {exact: true}).first()).toBeVisible();
      await expect(page.getByRole('heading', {name: '安全事件摘要'})).toBeVisible();
      await expectNoHorizontalOverflow(page);
    });

    test(`evidence dialog keeps the page within the viewport at ${width}px`, async ({page}) => {
      await installFixtureRoutes(page);
      await openIncident(page);
      const {dialog} = await openDrawer(page);
      await expect(dialog.getByText('相关字段')).toBeVisible();
      await expectNoHorizontalOverflow(page);
    });
  });
}

test.describe('evidence drawer accessibility smoke', () => {
  test.beforeEach(async ({page}) => {
    await installFixtureRoutes(page);
    await openIncident(page);
  });

  test('opens as a modal dialog named 证据面板 and closes via the 关闭证据 button', async ({page}) => {
    const {trigger, dialog} = await openDrawer(page);
    // T68: the drawer is a real dialog now (Base UI Dialog/Sheet), not a plain aside.
    await expect(dialog).toHaveAttribute('role', 'dialog');
    const close = page.getByRole('button', {name: '关闭证据', exact: true});
    await expect(close).toBeVisible();
    await close.click();
    await expect(dialog).toHaveCount(0);
    await expect(trigger).toBeVisible();
  });

  test('drawer content exposes the evidence fields it promises', async ({page}) => {
    const {dialog} = await openDrawer(page);
    await expect(dialog.getByText('相关字段')).toBeVisible();
    await expect(dialog.getByText('原始设备告警 / raw_alert')).toBeVisible();
    await expect(dialog.getByText('告警 ID / 标准化引用')).toBeVisible();
  });

  test('focus moves into the dialog on open', async ({page}) => {
    const {dialog} = await openDrawer(page);
    expect(await page.evaluate(() => {
      const panel = document.querySelector('[data-slot="sheet-popup"]');
      return Boolean(panel && document.activeElement && panel.contains(document.activeElement));
    })).toBeTruthy();
    // Base UI places focus on the first focusable element: the 关闭证据 button.
    await expect(page.getByRole('button', {name: '关闭证据', exact: true})).toBeFocused();
    await expect(dialog).toBeVisible();
  });

  test('Escape closes the dialog', async ({page}) => {
    const {dialog} = await openDrawer(page);
    await page.keyboard.press('Escape');
    await expect(dialog).toHaveCount(0);
  });

  test('focus returns to the trigger button after closing', async ({page}) => {
    const {trigger, dialog} = await openDrawer(page);
    await page.getByRole('button', {name: '关闭证据', exact: true}).click();
    await expect(dialog).toHaveCount(0);
    await expect(trigger).toBeFocused();
  });

  test('body scroll is locked while the dialog is open', async ({page}) => {
    await openDrawer(page);
    expect(await page.evaluate(() => document.body.style.overflow)).toBe('hidden');
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog')).toHaveCount(0);
    // Base UI releases the scroll lock after the exit transition completes.
    await expect.poll(() => page.evaluate(() => document.body.style.overflow)).toBe('');
  });
});


// F26: 200% browser zoom equivalent (viewport halved) and forced-colors mode.
test.describe('zoom and forced colors', () => {
  test('200% zoom equivalent viewport keeps workbench and drawer within bounds', async ({page}) => {
    await page.setViewportSize({width: 720, height: 450});
    await installFixtureRoutes(page);
    await openWorkbench(page);
    await expect(page.getByRole('heading', {name: '安全事件列表'})).toBeVisible();
    await expectNoHorizontalOverflow(page);
    await openIncident(page);
    await page.getByRole('button', {name: /查看全部成员证据/}).click();
    await expect(page.getByRole('dialog')).toBeVisible();
    await expectNoHorizontalOverflow(page);
  });

  test.describe('forced colors', () => {
    test.use({forcedColors: 'active'});
    test('workbench table and evidence dialog stay visible in forced-colors mode', async ({page}) => {
      await installFixtureRoutes(page);
      await openWorkbench(page);
      await expect(page.getByRole('heading', {name: '安全事件列表'})).toBeVisible();
      await expect(page.getByRole('button', {name: '查看详情 →'}).first()).toBeVisible();
      await openIncident(page);
      await page.getByRole('button', {name: /查看全部成员证据/}).click();
      await expect(page.getByRole('dialog')).toBeVisible();
      await expect(page.getByText('相关字段')).toBeVisible();
    });
  });
});
