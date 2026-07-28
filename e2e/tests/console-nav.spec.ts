import { expect, test } from '@playwright/test';
import { ADMIN_URL } from '../playwright.config';
import { authFile, profiles, scenarios, seeded } from '../lib/fixtures';

// Console navigation: the rail entries only show for the profiles that may
// use them (kind=ui scenarios), and "/" lands each profile on its own first
// screen. The role classes come from the gateway's body stamp — this suite
// exercises the real proxy + stamp chain, not a mocked identity.

for (const sc of scenarios.filter((s) => s.kind === 'ui')) {
  test.describe(sc.id, () => {
    for (const profile of profiles) {
      const visible = sc.allowed.includes(profile.id);
      test(`${sc.check!.railItem} is ${visible ? 'visible' : 'hidden'} for ${profile.id}`, async ({ browser }) => {
        const context = await browser.newContext({ storageState: authFile(profile.id) });
        const page = await context.newPage();
        await page.goto(ADMIN_URL + '/');
        const item = page.locator('rail-nav-item').filter({ hasText: sc.check!.railItem });
        if (visible) {
          await expect(item).toBeVisible();
        } else {
          // Role-CSS hides it (display:none); it may also be absent entirely.
          await expect(item).toBeHidden();
        }
        await context.close();
      });
    }
  });
}

// ui-landing (kind=flow, spec=console-nav): each profile's landing screen.
const LANDING: Record<string, RegExp> = {
  root: /\/routes$/,
  'infra-admin': /\/routes$/,
  'app-admin': /\/general$/,
  'tenant-admin': /\/tenants\/[^/]+/,
  user: /\/tenants(\/[^/]+)?/,
};

test.describe('ui-landing', () => {
  for (const profile of profiles) {
    test(`${profile.id} lands on its first screen`, async ({ browser }) => {
      seeded(); // fails fast if the setup did not run
      const context = await browser.newContext({ storageState: authFile(profile.id) });
      const page = await context.newPage();
      await page.goto(ADMIN_URL + '/');
      await expect(page).toHaveURL(LANDING[profile.id]);
      await context.close();
    });
  }
});
