import { Routes, UrlMatchResult, UrlSegment } from '@angular/router';
import { SectionShellComponent } from './shell/section-shell.component';
import {
  apiDocsAccess,
  appOnly,
  auditAccess,
  vaultAccess,
  firstTenantRedirect,
  infraOnly,
  landingRedirect,
  rootOnly,
} from './access.guards';

// The routes page owns routes, routes/new and routes/:id/:section through ONE
// route config: the SAME component instance survives every drawer open/close
// (no re-create, no re-fetch, one clean drawer animation), only the params
// change. A plain routes/:id counts as :id + the default section.
//
// As a CHILD of /infra the matcher sees the segments left after "infra", so it
// is written against "routes" either way.
function routesMatcher(segments: UrlSegment[]): UrlMatchResult | null {
  if (segments.length === 0 || segments[0].path !== 'routes' || segments.length > 3) return null;
  const posParams: Record<string, UrlSegment> = {};
  if (segments.length >= 2 && segments[1].path !== 'new') posParams['id'] = segments[1];
  if (segments.length === 3) posParams['section'] = segments[2];
  return { consumed: segments, posParams };
}

// users and users/:id, one config (see routesMatcher above).
function usersMatcher(segments: UrlSegment[]): UrlMatchResult | null {
  if (segments.length === 0 || segments[0].path !== 'users' || segments.length > 2) return null;
  const posParams: Record<string, UrlSegment> = {};
  if (segments.length === 2) posParams['id'] = segments[1];
  return { consumed: segments, posParams };
}

// auth-providers, auth-providers/new and auth-providers/:id.
function authProvidersMatcher(segments: UrlSegment[]): UrlMatchResult | null {
  if (segments.length === 0 || segments[0].path !== 'auth-providers' || segments.length > 2) return null;
  const posParams: Record<string, UrlSegment> = {};
  if (segments.length === 2 && segments[1].path !== 'new') posParams['id'] = segments[1];
  return { consumed: segments, posParams };
}

// roles, roles/new and roles/:id — same one-config trick.
function rolesMatcher(segments: UrlSegment[]): UrlMatchResult | null {
  if (segments.length === 0 || segments[0].path !== 'roles' || segments.length > 2) return null;
  const posParams: Record<string, UrlSegment> = {};
  if (segments.length === 2 && segments[1].path !== 'new') posParams['id'] = segments[1];
  return { consumed: segments, posParams };
}

export const routes: Routes = [
  // "/" resolves to the first section the user may use (infra admin →
  // routes, app admin → general, others → tenants).
  { path: '', pathMatch: 'full', canActivate: [landingRedirect], children: [] },

  // ── the infra plane ────────────────────────────────────────────────────────
  // Its sections are CHILDREN, so the shell hosting the left nav stays mounted
  // across them and the URL says which plane one is in.
  {
    path: 'infra',
    component: SectionShellComponent,
    data: { plane: 'infra' },
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'routes' },
      {
        // The editor drawer is URL-driven (F5-proof): routes/new opens a blank
        // one, routes/:id/:section opens that route on that section.
        matcher: routesMatcher,
        canActivate: [infraOnly],
        loadComponent: () =>
          import('./routes/routes-page/routes-page.component').then((m) => m.RoutesPageComponent),
      },
      {
        // Endpoint security (RBAC-07): a dedicated page with a route selector;
        // picking a route that exposes an OpenAPI spec loads its operations in
        // a swagger-like editor. Optional ?route=<id> preselects one.
        path: 'endpoint-security',
        canActivate: [infraOnly],
        loadComponent: () =>
          import('./routes/endpoint-security/endpoint-security.component').then(
            (m) => m.EndpointSecurityComponent,
          ),
      },
      {
        // External authentication (AUTH-19): a directory or an identity
        // provider is a third-party service, like an upstream or the relay.
        matcher: authProvidersMatcher,
        canActivate: [infraOnly],
        loadComponent: () =>
          import('./gateway/auth-providers/auth-providers-page.component').then(
            (m) => m.AuthProvidersPageComponent,
          ),
      },
      {
        path: 'mail-relay',
        canActivate: [infraOnly],
        loadComponent: () =>
          import('./gateway/mail-relay-page.component').then((m) => m.MailRelayPageComponent),
      },
      {
        path: 'access-tokens',
        canActivate: [rootOnly],
        loadComponent: () =>
          import('./gateway/access-tokens-page.component').then((m) => m.AccessTokensPageComponent),
      },
    ],
  },

  // ── the application plane ──────────────────────────────────────────────────
  {
    path: 'application',
    component: SectionShellComponent,
    data: { plane: 'application' },
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'general' },
      {
        path: 'general',
        canActivate: [appOnly],
        loadComponent: () => import('./settings/general-page.component').then((m) => m.GeneralPageComponent),
      },
      {
        path: 'locales',
        canActivate: [appOnly],
        loadComponent: () => import('./settings/locales-page.component').then((m) => m.LocalesPageComponent),
      },
      {
        // The role drawer is URL-driven too: roles/new opens a blank one,
        // roles/:id opens that role.
        matcher: rolesMatcher,
        canActivate: [appOnly],
        loadComponent: () =>
          import('./identity/roles-page/roles-page.component').then((m) => m.RolesPageComponent),
      },
      {
        // Same one-config trick as routes: users and users/:id share ONE
        // component instance, so opening the drawer never re-creates (nor
        // re-fetches) the page — only the params change.
        matcher: usersMatcher,
        canActivate: [appOnly],
        loadComponent: () =>
          import('./identity/users-page/users-page.component').then((m) => m.UsersPageComponent),
      },
      {
        // The URL follows the label: this screen is the built-in pages (their
        // theme AND branding), not just a theme.
        path: 'built-in-pages',
        canActivate: [appOnly],
        loadComponent: () =>
          import('./theme/theme-page/theme-page.component').then((m) => m.ThemePageComponent),
      },
      {
        path: 'security',
        canActivate: [appOnly],
        loadComponent: () =>
          import('./settings/security-page.component').then((m) => m.SecurityPageComponent),
      },
    ],
  },

  // ── transverse screens ─────────────────────────────────────────────────────
  // They belong to no single plane (the vault and the audit trail scope
  // themselves per caller), and a tenant brings its own left nav.
  {
    path: 'tenants',
    canActivate: [firstTenantRedirect],
    loadComponent: () => import('./identity/no-tenant.component').then((m) => m.NoTenantComponent),
  },
  // Every tenant section is a child ROUTE of the tenant layout: deep links
  // work, and the left nav's active state is plain routerLinkActive.
  {
    path: 'tenants/:id',
    loadComponent: () =>
      import('./identity/tenant-page/tenant-page.component').then((m) => m.TenantPageComponent),
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'general' },
      {
        path: 'general',
        loadComponent: () =>
          import('./identity/tenant-sections/tenant-general.component').then((m) => m.TenantGeneralComponent),
      },
      {
        path: 'groups',
        loadComponent: () =>
          import('./identity/tenant-sections/tenant-groups.component').then((m) => m.TenantGroupsComponent),
      },
      {
        path: 'members',
        loadComponent: () =>
          import('./identity/tenant-sections/tenant-members.component').then((m) => m.TenantMembersComponent),
      },
      {
        path: 'danger',
        loadComponent: () =>
          import('./identity/tenant-sections/tenant-danger.component').then((m) => m.TenantDangerComponent),
      },
    ],
  },
  {
    path: 'vault',
    canActivate: [vaultAccess],
    loadComponent: () => import('./gateway/vault-page.component').then((m) => m.VaultPageComponent),
  },
  {
    path: 'audit',
    canActivate: [auditAccess],
    loadComponent: () => import('./settings/audit-page.component').then((m) => m.AuditPageComponent),
  },
  {
    // The swagger-ui screen: an iframe over the gateway-served /apidocs/ page.
    path: 'api',
    canActivate: [apiDocsAccess],
    loadComponent: () => import('./gateway/api-docs-page.component').then((m) => m.ApiDocsPageComponent),
  },
  { path: '**', redirectTo: '' },
];
