import { expect, request, test } from '@playwright/test';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { ADMIN_URL, DATA_URL } from '../playwright.config';
import { authDataFile, authFile, seeded } from '../lib/fixtures';

// The gateway's own flow pages (data plane): sign-in hygiene, the profile
// pages' own guards, and the global passkey policy. Covers the kind=flow
// scenarios with spec=flow-pages in scenarios.json.

test('flow-login-bad-password: refused without a session', async ({ page }) => {
  await page.goto(DATA_URL + '/login');
  await page.fill('input[name=username]', 'alice');
  await page.fill('input[name=password]', 'definitely-wrong');
  await page.click('button[type=submit]');
  await expect(page.locator('p.error').first()).toBeVisible();
  const cookies = await page.context().cookies();
  expect(cookies.find((c) => c.name === 'MEERKAT_SESSION')).toBeUndefined();
});

test('flow-profile-history: a fresh sign-in shows with its method', async ({ browser }) => {
  const s = seeded();
  // A REAL browser sign-in (not the seeded state): this is the event the
  // history page must show, badged as this browser.
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(DATA_URL + '/login');
  await page.fill('input[name=username]', s.users['user'].username);
  await page.fill('input[name=password]', s.users['user'].password);
  await page.click('button[type=submit]');

  await page.goto(DATA_URL + '/profile/security');
  await page.click('a[href="/profile/history"]');
  await expect(page).toHaveURL(DATA_URL + '/profile/history');
  // THIS browser's row (badged through its fresh MEERKAT_BROWSER cookie)
  // simplifies to "This browser" + method, no browser/OS/IP.
  const mine = page.locator('.lh-row').filter({ has: page.locator('.lh-label.here') }).first();
  await expect(mine).toBeVisible();
  await expect(mine.locator('.lh-method')).toHaveText(/password/i);
  await context.close();
});

// flow-api-token: a user mints a personal token in the browser, then uses it
// as a Bearer to reach an authenticated data-plane route WITHOUT a session;
// revoking it closes the door.
test('flow-api-token: Bearer token authenticates API calls, revoke closes it', async ({ browser }) => {
  const context = await browser.newContext({ storageState: authDataFile('user') });
  const page = await context.newPage();
  await page.goto(DATA_URL + '/profile/tokens');
  // Creation happens in a modal: open it, fill, submit.
  await page.click('#tk-open');
  await page.fill('#tk-create-dlg input[name=name]', 'e2e-token');
  await page.selectOption('#tk-create-dlg select[name=days]', '90');
  await page.click('#tk-create-dlg button[value="create"]');

  // The token is revealed once in its own modal.
  const shown = await page.locator('#tk-reveal-dlg #tk-value').textContent();
  const token = (shown || '').trim();
  expect(token).toMatch(/^mk_/);
  await page.click('#tk-done');

  // The seeded "/secure" route is an AUTHENTICATED UI route. A fresh client
  // with NO cookies but the Bearer token gets through; without it, refused.
  // We assert the AUTH GATE (401 or not), not the upstream status, so the
  // test never depends on the demo upstream being reachable.
  const api = await request.newContext({ baseURL: DATA_URL });
  const withTok = await api.get('/secure/get', {
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
  });
  expect(withTok.status(), 'token must pass the auth gate').not.toBe(401);
  const without = await api.get('/secure/get', { headers: { Accept: 'application/json' } });
  expect(without.status()).toBe(401);

  // Revoke it in the browser (a confirm modal guards the destructive action).
  const row = page.locator('.tk').filter({ hasText: 'e2e-token' });
  await row.locator('button[data-revoke]').click();
  await page.click('#tk-revoke-dlg button[value="revoke"]');
  await expect(page.locator('.tk').filter({ hasText: 'e2e-token' })).toHaveCount(0);
  const afterRevoke = await api.get('/secure/get', {
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
  });
  expect(afterRevoke.status()).toBe(401);
  await api.dispose();
  await context.close();
});

test('flow-rate-limit: repeated failed sign-ins answer 429', async () => {
  const anon = await request.newContext({ baseURL: DATA_URL });
  // Default policy: 10 failed attempts per IP+account per 15 minutes. A
  // throwaway username keeps the other suites' accounts unaffected.
  for (let i = 0; i < 10; i++) {
    const res = await anon.post('/login', {
      form: { username: 'brute-ghost', password: 'nope-' + i },
      maxRedirects: 0,
    });
    expect(res.status(), `attempt ${i + 1}`).toBe(401);
  }
  const blocked = await anon.post('/login', {
    form: { username: 'brute-ghost', password: 'nope-final' },
    maxRedirects: 0,
  });
  expect(blocked.status()).toBe(429);
  await anon.dispose();
});

test('flow-profile-apps: the hub links back to the reachable applications', async ({ browser }) => {
  const context = await browser.newContext({ storageState: authDataFile('user') });
  const page = await context.newPage();
  await page.goto(DATA_URL + '/profile');
  // The seeded demo routes: /demo (public UI) and /secure (authenticated UI)
  // are both reachable for a signed-in user.
  await expect(page.locator('.apps a[href="/demo"]')).toBeVisible();
  await expect(page.locator('.apps a[href="/secure"]')).toBeVisible();
  await context.close();
});

test('flow-dev-page-forbidden: /profile/dev answers 403 to a non-dev', async ({ browser }) => {
  const context = await browser.newContext({ storageState: authDataFile('user') });
  const page = await context.newPage();
  const res = await page.goto(DATA_URL + '/profile/dev');
  expect(res?.status()).toBe(403);
  await context.close();
});

test('flow-privilege-escalation: an app admin cannot mint or promote a root', async () => {
  const s = seeded();
  const ctx = await request.newContext({ baseURL: ADMIN_URL, storageState: authFile('app-admin') });
  const created = await ctx.post('/api/users', { data: { username: 'evil-root', root: true } });
  expect(created.status()).toBe(403);
  const promoted = await ctx.put(`/api/users/${s.users['user'].id}`, {
    data: { username: 'alice', fullname: 'Alice Martin', enabled: true, root: true },
  });
  expect(promoted.status()).toBe(403);
  await ctx.dispose();
});

// flow-register-captcha: with the built-in captcha ON (the default when
// registration opens), the page carries the image and a wrong copy is
// refused without creating anything. Runs BEFORE flow-self-register, which
// then turns the captcha off for its scripted loop.
test('flow-register-captcha: a wrong copy is refused', async ({ page }) => {
  const root = await request.newContext({ baseURL: ADMIN_URL, storageState: authFile('root') });
  const settings = await (await root.get('/api/settings')).json();
  const put = await root.put('/api/settings', {
    data: {
      ...settings,
      smtp: { host: '127.0.0.1', port: 12525, security: 'none', username: '', from: 'Meerkat <no-reply@e2e.test>', password: '', passwordSet: false },
      selfRegistration: true,
      selfRegisterCaptcha: true,
    },
  });
  expect(put.ok(), await put.text()).toBeTruthy();
  await root.dispose();

  await page.goto(DATA_URL + '/register');
  await expect(page.locator('#cap-img')).toBeVisible();
  await page.fill('input[name=username]', 'robot');
  await page.fill('input[name=email]', 'robot@e2e.test');
  await page.fill('input[name=password]', 'brand-new-pass-1');
  await page.fill('input[name=confirm]', 'brand-new-pass-1');
  await page.fill('input[name=captcha]', '00000'); // 0 is not even in the alphabet
  await page.click('button[type=submit]');
  await expect(page.locator('p.error').first()).toBeVisible();
  // Still on the form, with a FRESH image to try again.
  await expect(page.locator('#cap-img')).toBeVisible();
});

// flow-self-register: the full loop against the SMTP sink — register, blocked
// until confirmed, mailed one-shot link, admin notified, waiting room. Lives
// in THIS file so its settings mutation stays serialized with the passkey
// test (same worker).
test('flow-self-register: end to end through the mailed confirmation', async ({ page }) => {
  const mailDir = join(__dirname, '..', '.tmp', 'mail');
  const root = await request.newContext({ baseURL: ADMIN_URL, storageState: authFile('root') });
  // Root gets an address so the "new account" notification has a recipient.
  const me = (await (await root.get('/api/me')).json()) as { user: Record<string, unknown> };
  const rootPut = await root.put('/api/users/admin', {
    data: { ...me.user, email: 'admin@e2e.test' },
  });
  expect(rootPut.ok(), await rootPut.text()).toBeTruthy();
  // Point the gateway at the sink and open self-registration.
  const settings = await (await root.get('/api/settings')).json();
  const put = await root.put('/api/settings', {
    data: {
      ...settings,
      smtp: { host: '127.0.0.1', port: 12525, security: 'none', username: '', from: 'Meerkat <no-reply@e2e.test>', password: '', passwordSet: false },
      selfRegistration: true,
      selfRegisterCaptcha: false, // the scripted loop skips the visual check
    },
  });
  expect(put.ok(), await put.text()).toBeTruthy();

  const findMail = (rcpt: string, needle: string): string | null => {
    if (!existsSync(mailDir)) return null;
    for (const f of readdirSync(mailDir)) {
      const m = JSON.parse(readFileSync(join(mailDir, f), 'utf8')) as { to: string[]; data: string };
      if (m.to.some((t) => t.includes(rcpt)) && m.data.includes(needle)) return m.data;
    }
    return null;
  };

  // Register through the real page.
  await page.goto(DATA_URL + '/register');
  await page.fill('input[name=username]', 'newcomer');
  await page.fill('input[name=email]', 'newcomer@e2e.test');
  await page.fill('input[name=password]', 'brand-new-pass-1');
  await page.fill('input[name=confirm]', 'brand-new-pass-1');
  await page.click('button[type=submit]');
  await expect(page.locator('p.lead').first()).toContainText(/inbox|boîte/i);

  // The confirmation mail lands in the sink; before opening it, the correct
  // password still cannot sign in.
  await expect.poll(() => findMail('newcomer@e2e.test', '/confirm?token='), { timeout: 10_000 }).toBeTruthy();
  const anon = await request.newContext({ baseURL: DATA_URL });
  const early = await anon.post('/login', {
    form: { username: 'newcomer', password: 'brand-new-pass-1' },
    maxRedirects: 0,
  });
  expect(early.status()).toBe(200); // "check your inbox", no 303, no session
  await anon.dispose();

  const raw = findMail('newcomer@e2e.test', '/confirm?token=')!;
  const link = raw.match(/http:\/\/[^\s"<]+\/confirm\?token=[A-Za-z0-9_-]+/)![0];
  await page.goto(link);
  await expect(page.locator('p.lead').first()).toContainText(/confirmed|confirmé/i);

  // Admins got their notification.
  await expect.poll(() => findMail('admin@e2e.test', 'newcomer'), { timeout: 10_000 }).toBeTruthy();

  // First sign-in lands on the waiting room, with the public route offered.
  await page.goto(DATA_URL + '/login');
  await page.fill('input[name=username]', 'newcomer');
  await page.fill('input[name=password]', 'brand-new-pass-1');
  await page.click('button[type=submit]');
  await expect(page).toHaveURL(DATA_URL + '/account-pending');
  await expect(page.locator('p.lead').first()).toContainText(/awaiting|attente/i);
  await root.dispose();
});

// flow-forgot-password: the reset loop through the SMTP sink, on the account
// the self-registration test just created (runs after it, same serial file).
test('flow-forgot-password: mailed link resets the password', async ({ page, browser }) => {
  const mailDir = join(__dirname, '..', '.tmp', 'mail');
  const findMail = (rcpt: string, needle: string): string | null => {
    if (!existsSync(mailDir)) return null;
    for (const f of readdirSync(mailDir)) {
      const m = JSON.parse(readFileSync(join(mailDir, f), 'utf8')) as { to: string[]; data: string };
      if (m.to.some((t) => t.includes(rcpt)) && m.data.includes(needle)) return m.data;
    }
    return null;
  };

  await page.goto(DATA_URL + '/login');
  await page.click('a[href="/forgot-password"]');
  await page.fill('input[name=email]', 'newcomer@e2e.test');
  await page.click('button[type=submit]');
  await expect(page.locator('p.lead').first()).toContainText(/inbox|boîte/i);

  await expect.poll(() => findMail('newcomer@e2e.test', '/reset-password?token='), { timeout: 10_000 }).toBeTruthy();
  const raw = findMail('newcomer@e2e.test', '/reset-password?token=')!;
  const link = raw.match(/http:\/\/[^\s"<]+\/reset-password\?token=[A-Za-z0-9_-]+/)![0];

  const context = await browser.newContext();
  const fresh = await context.newPage();
  await fresh.goto(link);
  await fresh.fill('input[name=password]', 'reset-ted-pass-1');
  await fresh.fill('input[name=confirm]', 'reset-ted-pass-1');
  await fresh.click('button[type=submit]');
  await expect(fresh.locator('p.lead').first()).toContainText(/updated|mis à jour/i);

  // The new password signs in (still no access: the waiting room).
  await fresh.goto(DATA_URL + '/login');
  await fresh.fill('input[name=username]', 'newcomer');
  await fresh.fill('input[name=password]', 'reset-ted-pass-1');
  await fresh.click('button[type=submit]');
  await expect(fresh).toHaveURL(DATA_URL + '/account-pending');
  await context.close();
});

// flow-select-group: EXCLUSIVE group mode end to end — the tenant is forced
// SINGLE, alice holds two groups, so her sign-in lands on the group choice;
// picking one completes the flow. Restores the tenant mode afterwards.
test('flow-select-group: exclusive mode asks which group at sign-in', async ({ browser }) => {
  const s = seeded();
  const root = await request.newContext({ baseURL: ADMIN_URL, storageState: authFile('root') });
  const tenant = await (await root.get(`/api/tenants/${s.tenantId}`)).json();
  try {
    const forced = await root.put(`/api/tenants/${s.tenantId}`, { data: { ...tenant, groupMode: 'SINGLE' } });
    expect(forced.ok(), await forced.text()).toBeTruthy();
    for (const name of ['e2e-blue', 'e2e-red']) {
      const res = await root.post(`/api/tenants/${s.tenantId}/groups`, { data: { name, roleIds: [] } });
      expect([200, 201, 422]).toContain(res.status()); // 422 = already there from a previous run
    }
    const groups = (await (await root.get(`/api/tenants/${s.tenantId}/groups`)).json()) as { id: string; name: string }[];
    const ids = groups.filter((g) => g.name.startsWith('e2e-')).map((g) => g.id);
    const assign = await root.put(`/api/tenants/${s.tenantId}/members/${s.users['user'].id}/groups`, { data: ids });
    expect(assign.ok(), await assign.text()).toBeTruthy();

    const context = await browser.newContext();
    const page = await context.newPage();
    await page.goto(DATA_URL + '/login?next=%2Fprofile');
    await page.fill('input[name=username]', s.users['user'].username);
    await page.fill('input[name=password]', s.users['user'].password);
    await page.click('button[type=submit]');
    await expect(page).toHaveURL(/\/select-group/);
    await expect(page.locator('button.choice')).toHaveCount(2);
    await page.locator('button.choice', { hasText: 'e2e-blue' }).click();
    await expect(page).toHaveURL(DATA_URL + '/profile');
    await context.close();
  } finally {
    await root.put(`/api/tenants/${s.tenantId}`, { data: { ...tenant, groupMode: tenant.groupMode || '' } });
    await root.dispose();
  }
});

// Mutates the GLOBAL passkey policy: keep it serial and restore whatever
// happens, so the rest of the suite never sees passkeys off.
test.describe.serial('flow-passkey-policy', () => {
  test('disabling passkeys hides the button and refuses the ceremonies', async ({ page }) => {
    const root = await request.newContext({ baseURL: ADMIN_URL, storageState: authFile('root') });
    const settings = await (await root.get('/api/settings')).json();
    try {
      await expect(async () => {
        const res = await root.put('/api/settings', { data: { ...settings, passkeysAllowed: false } });
        expect(res.ok(), await res.text()).toBeTruthy();
      }).toPass();

      await page.goto(DATA_URL + '/login');
      await expect(page.locator('#pk-login')).toHaveCount(0);
      const anon = await request.newContext({ baseURL: DATA_URL });
      expect((await anon.post('/login/passkey/start')).status()).toBe(403);
      await anon.dispose();
    } finally {
      const res = await root.put('/api/settings', { data: { ...settings, passkeysAllowed: true } });
      expect(res.ok()).toBeTruthy();
      await root.dispose();
    }
  });
});
