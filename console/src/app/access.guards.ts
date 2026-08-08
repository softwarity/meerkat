import { inject } from '@angular/core';
import { CanActivateFn, Router, RouterStateSnapshot, UrlTree } from '@angular/router';
import { catchError, firstValueFrom, map, of } from 'rxjs';
import { ApiService } from './api.service';
import { MeService } from './me.service';

// Where a user lands and falls back to (CONSOLE-02): an infra admin starts on
// the routing plane, an app admin on the application, everyone else on Tenants
// (any authenticated console user may open it - the API scopes the content).
// These guards are navigation comfort; the admin API enforces the same scopes
// server-side (RBAC-05).
function landing(me: MeService): string {
  if (me.isInfraAdmin()) return '/infra/routes';
  if (me.isAppAdmin()) return '/application/general';
  // /tenants does not exist in single-organisation mode, and License is the
  // one screen no guard can bounce anyone off: it is the honest destination
  // for someone who administers nothing here.
  return me.multiTenant() ? '/tenants' : '/license';
}

// bounce is how a guard refuses: it redirects, UNLESS that would send someone
// where they already are.
//
// A guard that returns a UrlTree pointing at its own route makes the router
// re-run it, decide the same thing, and navigate again - a synchronous loop
// that freezes the tab with a blank page and nothing in the console. It is not
// hypothetical: with no session nobody holds a capability, so landing() said
// "/tenants", and single-organisation mode closes /tenants and sent them back
// to landing(). Refusing outright leaves the browser where it is, which is
// exactly right - the 401 that caused it is already taking it to sign in.
function bounce(router: Router, state: RouterStateSnapshot, to: string): UrlTree | boolean {
  return state.url === to ? false : router.parseUrl(to);
}

// rootOnly gates the few root-reserved screens (e.g. control-plane access
// tokens): everyone else is redirected to their landing.
export const rootOnly: CanActivateFn = async (_route, state) => {
  const me = inject(MeService);
  const router = inject(Router);
  await me.ensureLoaded();
  return me.isRoot() ? true : bounce(router, state, landing(me));
};

// infraOnly gates the routing plane (routes, built-in pages): root or the
// infra-admin capability; others are redirected to their landing.
export const infraOnly: CanActivateFn = async (_route, state) => {
  const me = inject(MeService);
  const router = inject(Router);
  await me.ensureLoaded();
  return me.isInfraAdmin() ? true : bounce(router, state, landing(me));
};

// appOnly gates the application scope (general, users, roles, security): root
// or the app-admin capability.
export const appOnly: CanActivateFn = async (_route, state) => {
  const me = inject(MeService);
  const router = inject(Router);
  await me.ensureLoaded();
  return me.isAppAdmin() ? true : bounce(router, state, landing(me));
};

// multiTenantOnly closes the whole /tenants area in single mode. Not a
// permission - a shape: there is one organisation, it is never named, and its
// groups, members and rules are administered from Application. Someone landing
// here from a bookmark goes to their own landing rather than a screen about a
// notion this installation does not use.
export const multiTenantOnly: CanActivateFn = async (_route, state) => {
  const me = inject(MeService);
  const router = inject(Router);
  await me.ensureLoaded();
  return me.multiTenant() ? true : bounce(router, state, landing(me));
};

// vaultAccess gates the transverse Vault section: anyone administering a plane
// that holds entries (gateway or application). The API scopes the CONTENT to
// that plane; this only guards the page.
export const vaultAccess: CanActivateFn = async (_route, state) => {
  const me = inject(MeService);
  const router = inject(Router);
  await me.ensureLoaded();
  const ok = me.isRoot() || me.isInfraAdmin() || me.isAppAdmin();
  return ok ? true : bounce(router, state, landing(me));
};

// auditAccess gates the transverse Audit section: anyone who administers a
// domain may open it (root, infra-admin, app-admin, or a tenant admin). The
// API scopes the CONTENT to that domain; this only guards the page itself.
export const auditAccess: CanActivateFn = async (_route, state) => {
  const me = inject(MeService);
  const router = inject(Router);
  await me.ensureLoaded();
  const ok = me.isRoot() || me.isInfraAdmin() || me.isAppAdmin() || me.isTenantAdmin();
  return ok ? true : bounce(router, state, landing(me));
};

// issuesAccess gates the transverse Issues section: anyone who administers a
// domain may open it (root, infra-admin, app-admin, or a tenant admin). The
// API scopes the CONTENT (a tenant admin sees their tenants' reports only).
export const issuesAccess: CanActivateFn = async (_route, state) => {
  const me = inject(MeService);
  const router = inject(Router);
  await me.ensureLoaded();
  const ok = me.isRoot() || me.isInfraAdmin() || me.isAppAdmin() || me.isTenantAdmin();
  return ok ? true : bounce(router, state, landing(me));
};

// apiDocsAccess gates the API-docs screen: the capabilities that consume the
// control plane (root, infra-admin, app-admin). The spec LIST is scoped
// again server-side - route-declared specs need the routing plane.
export const apiDocsAccess: CanActivateFn = async (_route, state) => {
  const me = inject(MeService);
  const router = inject(Router);
  await me.ensureLoaded();
  const ok = me.isRoot() || me.isInfraAdmin() || me.isAppAdmin();
  return ok ? true : bounce(router, state, landing(me));
};

// landingRedirect sends "/" (and unknown paths) to the first section the user
// may use.
export const landingRedirect: CanActivateFn = async (_route, state) => {
  const me = inject(MeService);
  const router = inject(Router);
  await me.ensureLoaded();
  return bounce(router, state, landing(me));
};

// firstTenantRedirect: "/tenants" is not a page - it forwards to the first
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
