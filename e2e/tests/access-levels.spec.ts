import { expect, request, test } from '@playwright/test';
import { ADMIN_URL, CONSOLE_PORT, DATA_URL } from '../playwright.config';
import { authFile } from '../lib/fixtures';

// The belonging axis, over a real gateway (RBAC-06). This is the bug of
// 2026-08-06: signing in answered "your account is awaiting access" and the
// same session then walked through a route gated on authentication, reaching
// the application with no organisation and therefore no role.
//
// The rule for "auth" is unchanged on purpose - that level says who it is and
// nothing more, and it is how one serves the page explaining how to ask for
// access. What is new is that a route can demand an organisation, and that
// being refused for the lack of one LEADS SOMEWHERE.

const UPSTREAM = `http://localhost:${CONSOLE_PORT}`;
const NEWCOMER_PASSWORD = 'e2e-Newcomer-Pass-1';

test('flow-access-levels: a pending account passes "signed in" and is sent to the waiting room by "in an organisation"', async () => {
  const root = await request.newContext({ baseURL: ADMIN_URL, storageState: authFile('root') });

  // Two UI routes differing only by their level. A route is created by PUT on
  // its id (there is no POST /api/routes).
  const routeIds = ['e2e-auth', 'e2e-tenant'];
  for (const [id, level] of [
    ['e2e-auth', 'auth'],
    ['e2e-tenant', 'tenant'],
  ] as const) {
    const res = await root.put(`/api/routes/${id}`, {
      data: {
        id,
        name: id,
        order: 10, // ahead of the seeded catch-all, which would answer first
        enabled: true,
        isUI: true,
        upstream: UPSTREAM,
        access: { level },
        predicates: [{ type: 'path', args: { patterns: [`/${id}/**`] } }],
        filters: [{ type: 'strip-prefix', args: { parts: 1 } }],
      },
    });
    expect(res.ok(), await res.text()).toBeTruthy();
  }

  // Someone confirmed but granted nothing: no membership anywhere. Creation
  // answers a one-time password, and the first sign-in must spend it - a
  // session still pending a password change is not a session.
  const created = await root.post('/api/users', {
    data: { username: 'e2e-newcomer', fullname: 'New Comer', enabled: true },
  });
  expect(created.status(), await created.text()).toBe(201);
  const body = (await created.json()) as { user: { id: string }; password: string };

  const data = await request.newContext({ baseURL: DATA_URL });
  const signIn = await data.post('/login', {
    form: { username: 'e2e-newcomer', password: body.password },
    maxRedirects: 0,
  });
  expect(signIn.status(), 'the newcomer must be able to sign in').toBe(303);
  const settled = await data.post('/update-password', {
    form: { password: NEWCOMER_PASSWORD, confirm: NEWCOMER_PASSWORD },
    maxRedirects: 0,
  });
  expect(settled.status(), 'the one-time password must be spent').toBe(303);

  // "Signed in" takes them: deliberate, and the reason the level above exists.
  const onAuth = await data.get('/e2e-auth/en/', { maxRedirects: 0 });
  expect(onAuth.status(), 'a pending account must still pass a plain authenticated route').toBeLessThan(400);

  // "In an organisation" does not - and says where to go rather than 403.
  const onTenant = await data.get('/e2e-tenant/en/', { maxRedirects: 0 });
  expect(onTenant.status()).toBe(303);
  expect(onTenant.headers()['location']).toBe('/account-pending');

  await data.dispose();
  for (const id of routeIds) {
    expect((await root.delete(`/api/routes/${id}`)).ok()).toBeTruthy();
  }
  expect((await root.delete(`/api/users/${body.user.id}`)).ok()).toBeTruthy();
  await root.dispose();
});
