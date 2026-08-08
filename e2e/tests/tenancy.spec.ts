import { expect, request, test } from '@playwright/test';
import { ADMIN_URL } from '../playwright.config';
import { authFile } from '../lib/fixtures';

// The two shapes of an installation, switched live on a running gateway.
//
// This runs LAST and puts the mode back, because everything else in the suite
// is written against the multi-organisation console. What it proves is the
// thing a restart used to be needed for: the mode is read per request, so
// switching it takes effect at once - and going back down is allowed and
// deletes nothing, which is what makes the risk acceptable.
test('flow-tenancy-switch: single mode serves one organisation and gives the others back', async () => {
  const root = await request.newContext({ baseURL: ADMIN_URL, storageState: authFile('root') });

  const edition = async () => (await (await root.get('/api/edition')).json()) as {
    tenancy: string;
    hiddenTenants: number;
    tenancyLocked: boolean;
    enterprise: boolean;
  };

  const before = await edition();
  expect(before.tenancy, 'the suite runs against the multi-organisation console').toBe('multi');
  expect(before.enterprise).toBeTruthy();
  expect(before.tenancyLocked, 'with the feature, the switch is open').toBeFalsy();

  const tenantsBefore = ((await (await root.get('/api/tenants')).json()) as unknown[]).length;
  expect(tenantsBefore, 'the seed created one beside the one every install owns').toBeGreaterThan(1);

  // Down to one. Nothing is deleted: the others simply stop being served, and
  // the count is what the console's banner says out loud.
  const down = await root.put('/api/settings/tenancy', { data: { tenancy: 'single' } });
  expect(down.ok(), await down.text()).toBeTruthy();
  const single = await edition();
  expect(single.tenancy).toBe('single');
  expect(single.hiddenTenants).toBe(tenantsBefore - 1);
  expect(
    ((await (await root.get('/api/tenants')).json()) as unknown[]).length,
    'held back, not removed',
  ).toBe(tenantsBefore);

  // The console is served knowing it, on the very first paint - no class means
  // the multi-organisation screens would have flashed before disappearing.
  const html = await (await root.get('/en/', { headers: { Accept: 'text/html' } })).text();
  expect(html).toContain('data-meerkat-primary-tenant=');
  expect(html.match(/<body[^>]*>/)?.[0] ?? '').not.toContain('multi-tenant"');

  // And straight back, which is what makes the switch safe to try.
  const up = await root.put('/api/settings/tenancy', { data: { tenancy: 'multi' } });
  expect(up.ok(), await up.text()).toBeTruthy();
  expect((await edition()).tenancy).toBe('multi');
  expect((await edition()).hiddenTenants).toBe(0);

  await root.dispose();
});
