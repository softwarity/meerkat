import { Routes, UrlMatchResult, UrlSegment } from '@angular/router';
import {
  appOnly,
  auditAccess,
  firstTenantRedirect,
  gatewayOnly,
  landingRedirect,
  rootOnly,
} from './access.guards';

// The routes page owns /routes, /routes/new and /routes/:id/:section through
// ONE route config: the SAME component instance survives every drawer
// open/close (no re-create, no re-fetch, one clean drawer animation), only
// the params change. A plain /routes/:id counts as :id + the default section.
function routesMatcher(segments: UrlSegment[]): UrlMatchResult | null {
  if (segments.length === 0 || segments[0].path !== 'routes' || segments.length > 3) return null;
  const posParams: Record<string, UrlSegment> = {};
  if (segments.length >= 2 && segments[1].path !== 'new') posParams['id'] = segments[1];
  if (segments.length === 3) posParams['section'] = segments[2];
  return { consumed: segments, posParams };
}

export const routes: Routes = [
  // "/" resolves to the first section the user may use (gateway admin →
  // routes, app admin → general, others → tenants).
  { path: '', pathMatch: 'full', canActivate: [landingRedirect], children: [] },
  {
    // The editor drawer is URL-driven (F5-proof): /routes/new opens a blank
    // one, /routes/:id/:section opens that route on that section.
    matcher: routesMatcher,
    canActivate: [gatewayOnly],
    loadComponent: () =>
      import('./routes/routes-page/routes-page.component').then((m) => m.RoutesPageComponent),
  },
  {
    path: 'users',
    canActivate: [appOnly],
    loadComponent: () =>
      import('./identity/users-page/users-page.component').then((m) => m.UsersPageComponent),
  },
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
    // Endpoint security (RBAC-07): a dedicated Gateway page with a route
    // selector; picking a route that exposes an OpenAPI spec loads its
    // operations in a swagger-like editor. Optional ?route=<id> preselects one.
    path: 'endpoint-security',
    canActivate: [gatewayOnly],
    loadComponent: () =>
      import('./routes/endpoint-security/endpoint-security.component').then(
        (m) => m.EndpointSecurityComponent,
      ),
  },
  {
    path: 'theme',
    canActivate: [gatewayOnly],
    loadComponent: () =>
      import('./theme/theme-page/theme-page.component').then((m) => m.ThemePageComponent),
  },
  {
    path: 'access-tokens',
    canActivate: [rootOnly],
    loadComponent: () =>
      import('./gateway/access-tokens-page.component').then((m) => m.AccessTokensPageComponent),
  },
  {
    path: 'general',
    canActivate: [appOnly],
    loadComponent: () =>
      import('./settings/general-page.component').then((m) => m.GeneralPageComponent),
  },
  {
    path: 'locales',
    canActivate: [appOnly],
    loadComponent: () =>
      import('./settings/locales-page.component').then((m) => m.LocalesPageComponent),
  },
  {
    path: 'security',
    canActivate: [appOnly],
    loadComponent: () =>
      import('./settings/security-page.component').then((m) => m.SecurityPageComponent),
  },
  {
    path: 'roles',
    canActivate: [appOnly],
    loadComponent: () =>
      import('./identity/roles-page/roles-page.component').then((m) => m.RolesPageComponent),
  },
  {
    path: 'audit',
    canActivate: [auditAccess],
    loadComponent: () =>
      import('./settings/audit-page.component').then((m) => m.AuditPageComponent),
  },
  { path: '**', redirectTo: '' },
];
