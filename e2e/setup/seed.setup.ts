import { expect, request, test as setup, type APIRequestContext } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import { ADMIN_URL, DATA_URL, ROOT_PASSWORD } from '../playwright.config';
import { AUTH_DIR, authDataFile, authFile, type Seeded } from '../lib/fixtures';

// Seeds the five profiles THROUGH THE REAL FLOWS (no store shortcut): root
// creates the users over the admin API, each user signs in with its one-time
// password and completes the forced update-password step, and the resulting
// session is saved as that profile's storage state. Cookies are host-scoped
// (localhost), so one state serves both planes.

const USER_PASSWORD = 'e2e-User-Password-1';

// Redirects are never followed here: a successful step answers 303 and the
// landing target may be an app route (the data plane's catch-all) that has no
// reachable upstream in the test environment.
async function login(ctx: APIRequestContext, username: string, password: string): Promise<void> {
  const res = await ctx.post('/login', { form: { username, password }, maxRedirects: 0 });
  expect(res.status(), `login ${username}`).toBe(303);
}

// First login with a one-time password lands on the forced password change.
async function loginFirstTime(ctx: APIRequestContext, username: string, oneTime: string): Promise<void> {
  await login(ctx, username, oneTime);
  const res = await ctx.post('/update-password', {
    form: { password: USER_PASSWORD, confirm: USER_PASSWORD },
    maxRedirects: 0,
  });
  expect(res.status(), `update-password ${username}`).toBe(303);
  const me = await ctx.get('/api/me');
  expect(me.ok(), `session incomplete for ${username}`).toBeTruthy();
}

setup('seed profiles and tenant', async () => {
  mkdirSync(AUTH_DIR, { recursive: true });

  const root = await request.newContext({ baseURL: ADMIN_URL });
  await login(root, 'admin', ROOT_PASSWORD);
  expect((await root.get('/api/me')).ok()).toBeTruthy();

  // The data-plane developer docs ship OFF; the seed flips the Others-screen
  // switch the way an infra admin would, so future data-plane checks can rely
  // on it. The console docs (Meerkat's own spec) need no switch.
  expect((await root.put('/api/settings/api-docs', { data: { exposed: true } })).ok()).toBeTruthy();
  // Same for the issue tracker (ISSUE-04): on, so the matrix exercises /api/issues.
  expect((await root.put('/api/settings/issues', { data: { enabled: true } })).ok()).toBeTruthy();

  const create = async (user: Record<string, unknown>) => {
    const res = await root.post('/api/users', { data: user });
    expect(res.status(), `create ${user.username}: ${await res.text()}`).toBe(201);
    const body = (await res.json()) as { user: { id: string }; password: string };
    return { id: body.user.id, oneTime: body.password };
  };

  const gwadmin = await create({ username: 'gwadmin', enabled: true, infraAdmin: true });
  const appadmin = await create({ username: 'appadmin', enabled: true, appAdmin: true });
  const tadmin = await create({ username: 'tadmin', enabled: true });
  const alice = await create({ username: 'alice', enabled: true, fullname: 'Alice Martin' });

  // The acme tenant: tadmin administers it, alice is a plain member.
  const tenantRes = await root.post('/api/tenants', { data: { name: 'acme' } });
  expect(tenantRes.status(), await tenantRes.text()).toBe(201);
  const tenantId = ((await tenantRes.json()) as { id: string }).id;
  for (const [userId, type] of [
    [tadmin.id, 'ADMIN'],
    [alice.id, 'USER'],
  ] as const) {
    const res = await root.put(`/api/tenants/${tenantId}/members/${userId}`, {
      data: { userId, tenantId, type, enabled: true, businessAccess: { inherited: true }, sessionTTL: '' },
    });
    expect(res.ok(), await res.text()).toBeTruthy();
  }

  await root.storageState({ path: authFile('root') });

  // Each plane keeps its own session cookie: sign the profile in on the DATA
  // plane too and save that state separately (flow-page suites use it).
  const dataLogin = async (profile: string, username: string, password: string) => {
    const ctx = await request.newContext({ baseURL: DATA_URL });
    await login(ctx, username, password);
    await ctx.storageState({ path: authDataFile(profile) });
    await ctx.dispose();
  };
  await dataLogin('root', 'admin', ROOT_PASSWORD);

  const seededUsers: Seeded['users'] = {
    root: { id: 'root', username: 'admin', password: ROOT_PASSWORD },
  };
  for (const [profile, u] of [
    ['infra-admin', { ...gwadmin, username: 'gwadmin' }],
    ['app-admin', { ...appadmin, username: 'appadmin' }],
    ['tenant-admin', { ...tadmin, username: 'tadmin' }],
    ['user', { ...alice, username: 'alice' }],
  ] as const) {
    const ctx = await request.newContext({ baseURL: ADMIN_URL });
    await loginFirstTime(ctx, u.username, u.oneTime);
    await ctx.storageState({ path: authFile(profile) });
    seededUsers[profile] = { id: u.id, username: u.username, password: USER_PASSWORD };
    await ctx.dispose();
    await dataLogin(profile, u.username, USER_PASSWORD);
  }

  const seeded: Seeded = { tenantId, users: seededUsers };
  writeFileSync(`${AUTH_DIR}/seeded.json`, JSON.stringify(seeded, null, 2));
  await root.dispose();
});
