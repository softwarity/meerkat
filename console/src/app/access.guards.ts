import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { catchError, firstValueFrom, map, of } from 'rxjs';
import { ApiService } from './api.service';
import { MeService } from './me.service';

// Where a user lands and falls back to (CONSOLE-02): an infra admin starts on
// the routing plane, an app admin on the application, everyone else on Tenants
// (any authenticated console user may open it — the API scopes the content).
// These guards are navigation comfort; the admin API enforces the same scopes
// server-side (RBAC-05).
function landing(me: MeService): string {
  if (me.isInfraAdmin()) return '/infra/routes';
  if (me.isAppAdmin()) return '/application/general';
  return '/tenants';
}

// rootOnly gates the few root-reserved screens (e.g. control-plane access
// tokens): everyone else is redirected to their landing.
export const rootOnly: CanActivateFn = async () => {
  const me = inject(MeService);
  const router = inject(Router);
  await me.ensureLoaded();
  return me.isRoot() ? true : router.parseUrl(landing(me));
};

// infraOnly gates the routing plane (routes, built-in pages): root or the
// infra-admin capability; others are redirected to their landing.
export const infraOnly: CanActivateFn = async () => {
  const me = inject(MeService);
  const router = inject(Router);
  await me.ensureLoaded();
  return me.isInfraAdmin() ? true : router.parseUrl(landing(me));
};

// appOnly gates the application scope (general, users, roles, security): root
// or the app-admin capability.
export const appOnly: CanActivateFn = async () => {
  const me = inject(MeService);
  const router = inject(Router);
  await me.ensureLoaded();
  return me.isAppAdmin() ? true : router.parseUrl(landing(me));
};

// vaultAccess gates the transverse Vault section: anyone administering a plane
// that holds entries (gateway or application). The API scopes the CONTENT to
// that plane; this only guards the page.
export const vaultAccess: CanActivateFn = async () => {
  const me = inject(MeService);
  const router = inject(Router);
  await me.ensureLoaded();
  const ok = me.isRoot() || me.isInfraAdmin() || me.isAppAdmin();
  return ok ? true : router.parseUrl(landing(me));
};

// auditAccess gates the transverse Audit section: anyone who administers a
// domain may open it (root, infra-admin, app-admin, or a tenant admin). The
// API scopes the CONTENT to that domain; this only guards the page itself.
export const auditAccess: CanActivateFn = async () => {
  const me = inject(MeService);
  const router = inject(Router);
  await me.ensureLoaded();
  const ok = me.isRoot() || me.isInfraAdmin() || me.isAppAdmin() || me.isTenantAdmin();
  return ok ? true : router.parseUrl(landing(me));
};

// issuesAccess gates the transverse Issues section: anyone who administers a
// domain may open it (root, infra-admin, app-admin, or a tenant admin). The
// API scopes the CONTENT (a tenant admin sees their tenants' reports only).
export const issuesAccess: CanActivateFn = async () => {
  const me = inject(MeService);
  const router = inject(Router);
  await me.ensureLoaded();
  const ok = me.isRoot() || me.isInfraAdmin() || me.isAppAdmin() || me.isTenantAdmin();
  return ok ? true : router.parseUrl(landing(me));
};

// apiDocsAccess gates the API-docs screen: the capabilities that consume the
// control plane (root, infra-admin, app-admin). The spec LIST is scoped
// again server-side — route-declared specs need the routing plane.
export const apiDocsAccess: CanActivateFn = async () => {
  const me = inject(MeService);
  const router = inject(Router);
  await me.ensureLoaded();
  const ok = me.isRoot() || me.isInfraAdmin() || me.isAppAdmin();
  return ok ? true : router.parseUrl(landing(me));
};

// landingRedirect sends "/" (and unknown paths) to the first section the user
// may use.
export const landingRedirect: CanActivateFn = async () => {
  const me = inject(MeService);
  const router = inject(Router);
  await me.ensureLoaded();
  return router.parseUrl(landing(me));
};

// firstTenantRedirect: "/tenants" is not a page — it forwards to the first
// tenant the user may administer (sections are child routes of the tenant).
// With no tenant at all, the bare component under this route says so.
export const firstTenantRedirect: CanActivateFn = async () => {
  const api = inject(ApiService);
  const router = inject(Router);
  return firstValueFrom(
    api.listTenants().pipe(
      map((tenants) => (tenants.length ? router.parseUrl(`/tenants/${tenants[0].id}`) : true)),
      catchError(() => of(true)),
    ),
  );
};
