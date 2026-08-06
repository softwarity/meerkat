import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, signal, viewChild } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { MatButtonModule } from '@angular/material/button';
import { MatExpansionModule } from '@angular/material/expansion';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatSelectModule } from '@angular/material/select';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatSort, MatSortModule, Sort } from '@angular/material/sort';
import { MatTable, MatTableModule } from '@angular/material/table';
import { MatTooltipModule } from '@angular/material/tooltip';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { sessionStored } from '@softwarity/store';
import { Subject, catchError, debounceTime, firstValueFrom, of } from 'rxjs';
import {
  Access,
  ApiService,
  EndpointPolicy,
  OpenAPIOperation,
  Role,
  Route,
  RouteOperations,
  RouteSecurity,
  Tenant,
  User,
} from '../../api.service';
import { AccessBadgesComponent } from './access-badges.component';
import { AccessEditorComponent, AccessState, emptyAccess, isEmpty } from './access-editor.component';

// One operation's editable state: whether it overrides the route-wide default,
// and (when it does) its own access rule.
interface OpState {
  override: boolean;
  access: AccessState;
}

function opKey(method: string, path: string): string {
  return `${method.toUpperCase()} ${path}`;
}

// Conventional verb order for the method sort.
const METHOD_ORDER = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
function methodRank(m: string): number {
  const i = METHOD_ORDER.indexOf(m.toUpperCase());
  return i < 0 ? METHOD_ORDER.length : i;
}

// Turn the editor's non-optional access into the wire shape (a delegated level
// and empty lists are simply omitted).
function toPolicy(method: string, path: string, a: AccessState): EndpointPolicy {
  const ep: EndpointPolicy = { method: method.toUpperCase(), path };
  if (a.level) ep.level = a.level;
  if (a.tenants.length) ep.tenants = a.tenants;
  if (a.roles.length) ep.roles = a.roles;
  if (a.users.length) ep.users = a.users;
  return ep;
}

function fromWire(a: Access | undefined): AccessState {
  return {
    level: a?.level ?? '',
    tenants: a?.tenants ?? [],
    roles: a?.roles ?? [],
    users: a?.users ?? [],
  };
}

// Endpoint security (RBAC-07): a dedicated Gateway page. Pick a route that
// exposes an OpenAPI spec; its operations load in a table (sticky header,
// scrolling rows, global Save in the footer). One access rule (authenticated /
// users / roles) is set for the WHOLE route in the header, and any operation
// can override it by expanding its row. The spec is fetched and parsed
// SERVER-SIDE, so this screen only ever sees a flat operation list. Saving PUTs
// the assembled security to the admin API, which validates by compiling and
// reloads the data plane (saving IS applying).
@Component({
  selector: 'app-endpoint-security',
  imports: [
    RouterLink,
    MatButtonModule,
    MatExpansionModule,
    MatFormFieldModule,
    MatIconModule,
    MatProgressBarModule,
    MatSelectModule,
    MatSlideToggleModule,
    MatSortModule,
    MatTableModule,
    MatTooltipModule,
    AccessEditorComponent,
    AccessBadgesComponent,
  ],
  templateUrl: './endpoint-security.component.html',
  styleUrl: './endpoint-security.component.scss',
})
export class EndpointSecurityComponent {
  private readonly api = inject(ApiService);
  private readonly table = viewChild(MatTable);

  protected readonly loadingRoutes = signal(true);
  protected readonly loadingOps = signal(false);
  protected readonly error = signal('');
  // Auto-save: every change persists on its own (debounced); the footer shows
  // the state rather than a Save button.
  protected readonly saveState = signal<'idle' | 'saving' | 'saved' | 'error'>('idle');
  protected readonly saveError = signal('');
  private readonly saveTrigger = new Subject<void>();
  protected readonly routes = signal<Route[]>([]);
  protected readonly roles = signal<Role[]>([]);
  protected readonly users = signal<User[]>([]);
  protected readonly tenants = signal<Tenant[]>([]);
  protected readonly selectedId = signal('');
  protected readonly data = signal<RouteOperations | null>(null);

  // The route-wide default rule (applies to every operation with no override).
  protected readonly routeAccess = signal<AccessState>(emptyAccess());
  // Per-operation edits, keyed by opKey.
  private readonly state = signal<Record<string, OpState>>({});
  // Saved overrides that match no listed operation: kept so a save never
  // silently drops policy.
  private readonly extras = signal<EndpointPolicy[]>([]);
  // Exclusive expand: at most one row is open for editing at a time.
  private readonly expanded = signal<string>('');

  protected readonly apiRoutes = computed(() => this.routes().filter((r) => !!r.api?.openapiUrl));
  protected readonly operations = computed(() => this.data()?.operations ?? []);
  protected readonly columns = ['status', 'method', 'path', 'tags', 'summary', 'expand'];

  // Distinct tags across the spec, for the column-header filter.
  protected readonly allTags = computed(() => {
    const set = new Set<string>();
    for (const o of this.operations()) for (const t of o.tags ?? []) set.add(t);
    return [...set].sort((a, b) => a.localeCompare(b));
  });
  // Sort + method/tag filters persisted in sessionStorage: they survive a page
  // refresh (not the session). $prop() signals drive the template and computeds.
  protected readonly view = sessionStored(
    {
      sortActive: '',
      sortDir: '' as '' | 'asc' | 'desc',
      methods: [] as string[],
      tags: [] as string[],
      routeOpen: true, // the "whole route" panel is expanded by default
    },
    { storageKey: 'endpoint-security-view.v3' },
  );

  // Distinct methods present, in conventional verb order, for the header filter.
  protected readonly allMethods = computed(() => {
    const set = new Set<string>();
    for (const o of this.operations()) set.add(o.method.toUpperCase());
    return [...set].sort((a, b) => methodRank(a) - methodRank(b));
  });

  protected setTagFilter(tags: string[]): void {
    this.view.tags = tags;
    this.table()?.renderRows();
  }
  protected setMethodFilter(methods: string[]): void {
    this.view.methods = methods;
    this.table()?.renderRows();
  }
  protected onSort(s: Sort): void {
    this.view.sortActive = s.active;
    this.view.sortDir = s.direction;
    this.table()?.renderRows();
  }
  // The rows the table shows: filtered by method and tags, then sorted (path only).
  protected readonly sortedOps = computed(() => {
    const methods = this.view.$methods();
    const tags = this.view.$tags();
    let ops = this.operations();
    if (methods.length) ops = ops.filter((o) => methods.includes(o.method.toUpperCase()));
    if (tags.length) ops = ops.filter((o) => (o.tags ?? []).some((t) => tags.includes(t)));
    ops = [...ops];
    const active = this.view.$sortActive();
    const dir = this.view.$sortDir();
    if (!dir) return ops;
    const mul = dir === 'asc' ? 1 : -1;
    ops.sort((a, b) => {
      const byMethod = methodRank(a.method) - methodRank(b.method) || a.path.localeCompare(b.path);
      const byPath = a.path.localeCompare(b.path) || methodRank(a.method) - methodRank(b.method);
      return (active === 'method' ? byMethod : byPath) * mul;
    });
    return ops;
  });

  // Operations whose EFFECTIVE access gates something, plus the preserved extras.
  protected readonly securedCount = computed(() => {
    let n = this.extras().length;
    for (const o of this.operations()) if (!isEmpty(this.effective(o))) n++;
    return n;
  });

  constructor() {
    const preselect = inject(ActivatedRoute).snapshot.queryParamMap.get('route') ?? '';
    // Coalesce rapid edits (e.g. picking several roles) into one PUT.
    this.saveTrigger.pipe(debounceTime(500), takeUntilDestroyed()).subscribe(() => void this.persist());
    void this.init(preselect);
  }

  // A user edit happened: reflect it immediately, then persist after the debounce.
  private scheduleSave(): void {
    this.saveState.set('saving');
    this.saveTrigger.next();
  }

  private async init(preselect: string): Promise<void> {
    this.loadingRoutes.set(true);
    this.error.set('');
    try {
      // Roles, users and organisations are app-scoped: tolerate a 403 for a
      // pure gateway admin (the rule can still be set to a level that names
      // nothing).
      const [routes, roles, users, tenants] = await Promise.all([
        firstValueFrom(this.api.listRoutes()),
        firstValueFrom(this.api.listRoles().pipe(catchError(() => of<Role[]>([])))),
        firstValueFrom(this.api.listUsers().pipe(catchError(() => of<User[]>([])))),
        firstValueFrom(this.api.listTenants().pipe(catchError(() => of<Tenant[]>([])))),
      ]);
      this.roles.set(roles);
      this.users.set(users);
      this.tenants.set(tenants);
      this.routes.set(routes);
      const exposing = routes.filter((r) => !!r.api?.openapiUrl);
      const pick = exposing.find((r) => r.id === preselect)?.id ?? exposing[0]?.id ?? '';
      if (pick) await this.selectRoute(pick);
    } catch (e) {
      this.error.set(this.message(e));
    } finally {
      this.loadingRoutes.set(false);
    }
  }

  protected async selectRoute(id: string): Promise<void> {
    this.selectedId.set(id);
    this.data.set(null);
    this.expanded.set('');
    this.error.set('');
    if (!id) return;
    this.loadingOps.set(true);
    try {
      const ops = await firstValueFrom(this.api.getRouteOperations(id));
      this.seed(ops);
      this.data.set(ops);
      // Keep only the persisted filters that this route actually has.
      const knownTags = new Set<string>();
      const knownMethods = new Set<string>();
      for (const o of ops.operations) {
        knownMethods.add(o.method.toUpperCase());
        for (const t of o.tags ?? []) knownTags.add(t);
      }
      this.view.tags = this.view.tags.filter((t) => knownTags.has(t));
      this.view.methods = this.view.methods.filter((m) => knownMethods.has(m));
    } catch (e) {
      this.error.set(this.message(e));
    } finally {
      this.loadingOps.set(false);
    }
  }

  private seed(ops: RouteOperations): void {
    // The "whole route" default is the route's own Access now; overrides come
    // from the endpoint-security block.
    this.routeAccess.set(fromWire(ops.access));
    const saved = new Map<string, EndpointPolicy>();
    for (const e of ops.security?.endpoints ?? []) saved.set(opKey(e.method, e.path), e);

    const st: Record<string, OpState> = {};
    const matched = new Set<string>();
    for (const o of ops.operations) {
      const k = opKey(o.method, o.path);
      const p = saved.get(k);
      if (p) {
        st[k] = { override: true, access: fromWire(p) };
        matched.add(k);
      } else {
        st[k] = { override: false, access: emptyAccess() };
      }
    }
    this.state.set(st);
    this.extras.set((ops.security?.endpoints ?? []).filter((e) => !matched.has(opKey(e.method, e.path))));
  }

  // ── Row expand / collapse (exclusive: one open at a time) ───────────────────
  protected toggle(o: OpenAPIOperation): void {
    const k = opKey(o.method, o.path);
    this.expanded.set(this.expanded() === k ? '' : k);
    this.table()?.renderRows();
  }

  protected isExpanded(o: OpenAPIOperation): boolean {
    return this.expanded() === opKey(o.method, o.path);
  }

  protected readonly isDetailRow = (_: number, o: OpenAPIOperation): boolean => this.isExpanded(o);

  // ── Access state ───────────────────────────────────────────────────────────
  protected stateOf(o: OpenAPIOperation): OpState {
    return this.state()[opKey(o.method, o.path)] ?? { override: false, access: emptyAccess() };
  }

  // The rule actually in force for an operation: its override, or the route default.
  protected effective(o: OpenAPIOperation): AccessState {
    const s = this.stateOf(o);
    return s.override ? s.access : this.routeAccess();
  }

  // The route-wide default changed.
  protected setRouteAccess(a: AccessState): void {
    this.routeAccess.set(a);
    this.scheduleSave();
  }

  protected setOpAccess(o: OpenAPIOperation, access: AccessState): void {
    const k = opKey(o.method, o.path);
    this.state.update((s) => ({ ...s, [k]: { override: true, access } }));
    this.scheduleSave();
  }

  // Toggle whether an operation overrides the route default. Turning it on seeds
  // from the route default so the admin edits a concrete starting point.
  protected setOverride(o: OpenAPIOperation, on: boolean): void {
    const k = opKey(o.method, o.path);
    this.state.update((s) => {
      const cur = s[k] ?? { override: false, access: emptyAccess() };
      if (!on) return { ...s, [k]: { override: false, access: emptyAccess() } };
      const seed = isEmpty(cur.access) ? { ...this.routeAccess() } : cur.access;
      return { ...s, [k]: { override: true, access: seed } };
    });
    this.scheduleSave();
  }

  // ── Save ───────────────────────────────────────────────────────────────────
  private async persist(): Promise<void> {
    const id = this.selectedId();
    if (!id) return;
    const endpoints: EndpointPolicy[] = [];
    for (const o of this.operations()) {
      const s = this.state()[opKey(o.method, o.path)];
      if (!s?.override) continue;
      endpoints.push(toPolicy(o.method, o.path, s.access));
    }
    endpoints.push(...this.extras());
    const ra = this.routeAccess();
    const security: RouteSecurity = {
      access: {
        ...(ra.level ? { level: ra.level } : {}),
        ...(ra.tenants.length ? { tenants: ra.tenants } : {}),
        ...(ra.roles.length ? { roles: ra.roles } : {}),
        ...(ra.users.length ? { users: ra.users } : {}),
      },
      endpoints,
    };

    this.saveState.set('saving');
    try {
      await firstValueFrom(this.api.saveRouteSecurity(id, security));
      this.saveState.set('saved');
    } catch (e) {
      this.saveError.set(this.message(e));
      this.saveState.set('error');
    }
  }

  private message(e: unknown): string {
    const err = e as HttpErrorResponse;
    const body = err?.error as { error?: string } | undefined;
    if (typeof body?.error === 'string') return body.error;
    if (typeof err?.message === 'string') return err.message;
    return $localize`:@@Request_failed:Request failed`;
  }
}
