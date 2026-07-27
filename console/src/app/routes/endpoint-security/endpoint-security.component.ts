import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, signal, viewChild } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatSelectModule } from '@angular/material/select';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatTable, MatTableModule } from '@angular/material/table';
import { MatTooltipModule } from '@angular/material/tooltip';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { catchError, firstValueFrom, of } from 'rxjs';
import {
  ApiService,
  EndpointPolicy,
  EndpointSecurity,
  OpenAPIOperation,
  Role,
  Route,
  RouteOperations,
  User,
} from '../../api.service';
import { AccessEditorComponent, AccessState, emptyAccess, isPublic } from './access-editor.component';

// One operation's editable state: whether it overrides the route-wide default,
// and (when it does) its own access rule.
interface OpState {
  override: boolean;
  access: AccessState;
}

function opKey(method: string, path: string): string {
  return `${method.toUpperCase()} ${path}`;
}

// Turn the editor's non-optional access into the wire shape (empty lists and a
// false flag are simply omitted).
function toPolicy(method: string, path: string, a: AccessState): EndpointPolicy {
  const ep: EndpointPolicy = { method: method.toUpperCase(), path };
  if (a.authenticated) ep.authenticated = true;
  if (a.users.length) ep.users = a.users;
  if (a.roles.length) ep.roles = a.roles;
  return ep;
}

function fromWire(a: { authenticated?: boolean; users?: string[]; roles?: string[] } | undefined): AccessState {
  return { authenticated: !!a?.authenticated, users: a?.users ?? [], roles: a?.roles ?? [] };
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
    MatFormFieldModule,
    MatIconModule,
    MatProgressBarModule,
    MatSelectModule,
    MatSlideToggleModule,
    MatTableModule,
    MatTooltipModule,
    AccessEditorComponent,
  ],
  templateUrl: './endpoint-security.component.html',
  styleUrl: './endpoint-security.component.scss',
})
export class EndpointSecurityComponent {
  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);
  private readonly table = viewChild(MatTable);

  protected readonly loadingRoutes = signal(true);
  protected readonly loadingOps = signal(false);
  protected readonly saving = signal(false);
  protected readonly error = signal('');
  protected readonly routes = signal<Route[]>([]);
  protected readonly roles = signal<Role[]>([]);
  protected readonly users = signal<User[]>([]);
  protected readonly selectedId = signal('');
  protected readonly data = signal<RouteOperations | null>(null);

  // The route-wide default rule (applies to every operation with no override).
  protected readonly routeAccess = signal<AccessState>(emptyAccess());
  // Per-operation edits, keyed by opKey.
  private readonly state = signal<Record<string, OpState>>({});
  // Saved overrides that match no listed operation: kept so a save never
  // silently drops policy.
  private readonly extras = signal<EndpointPolicy[]>([]);
  private readonly expanded = signal<Set<string>>(new Set());

  protected readonly apiRoutes = computed(() => this.routes().filter((r) => !!r.api?.swaggerUrl));
  protected readonly operations = computed(() => this.data()?.operations ?? []);
  protected readonly columns = ['status', 'method', 'path', 'summary', 'expand'];

  // Operations whose EFFECTIVE access gates something, plus the preserved extras.
  protected readonly securedCount = computed(() => {
    let n = this.extras().length;
    for (const o of this.operations()) if (!isPublic(this.effective(o))) n++;
    return n;
  });

  constructor() {
    const preselect = inject(ActivatedRoute).snapshot.queryParamMap.get('route') ?? '';
    void this.init(preselect);
  }

  private async init(preselect: string): Promise<void> {
    this.loadingRoutes.set(true);
    this.error.set('');
    try {
      // Roles and users are app-scoped: tolerate a 403 for a pure gateway admin
      // (the rule can still be set to plain authenticated).
      const [routes, roles, users] = await Promise.all([
        firstValueFrom(this.api.listRoutes()),
        firstValueFrom(this.api.listRoles().pipe(catchError(() => of<Role[]>([])))),
        firstValueFrom(this.api.listUsers().pipe(catchError(() => of<User[]>([])))),
      ]);
      this.roles.set(roles);
      this.users.set(users);
      this.routes.set(routes);
      const exposing = routes.filter((r) => !!r.api?.swaggerUrl);
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
    this.expanded.set(new Set());
    this.error.set('');
    if (!id) return;
    this.loadingOps.set(true);
    try {
      const ops = await firstValueFrom(this.api.getRouteOperations(id));
      this.seed(ops);
      this.data.set(ops);
    } catch (e) {
      this.error.set(this.message(e));
    } finally {
      this.loadingOps.set(false);
    }
  }

  private seed(ops: RouteOperations): void {
    const sec = ops.security ?? {};
    this.routeAccess.set(fromWire(sec.route));
    const saved = new Map<string, EndpointPolicy>();
    for (const e of sec.endpoints ?? []) saved.set(opKey(e.method, e.path), e);

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
    this.extras.set((sec.endpoints ?? []).filter((e) => !matched.has(opKey(e.method, e.path))));
  }

  // ── Row expand / collapse ──────────────────────────────────────────────────
  protected toggle(o: OpenAPIOperation): void {
    const k = opKey(o.method, o.path);
    this.expanded.update((s) => {
      const next = new Set(s);
      if (!next.delete(k)) next.add(k);
      return next;
    });
    this.table()?.renderRows();
  }

  protected isExpanded(o: OpenAPIOperation): boolean {
    return this.expanded().has(opKey(o.method, o.path));
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

  protected setOpAccess(o: OpenAPIOperation, access: AccessState): void {
    const k = opKey(o.method, o.path);
    this.state.update((s) => ({ ...s, [k]: { override: true, access } }));
  }

  // Toggle whether an operation overrides the route default. Turning it on seeds
  // from the route default so the admin edits a concrete starting point.
  protected setOverride(o: OpenAPIOperation, on: boolean): void {
    const k = opKey(o.method, o.path);
    this.state.update((s) => {
      const cur = s[k] ?? { override: false, access: emptyAccess() };
      if (!on) return { ...s, [k]: { override: false, access: emptyAccess() } };
      const seed = isPublic(cur.access) ? { ...this.routeAccess() } : cur.access;
      return { ...s, [k]: { override: true, access: seed } };
    });
  }

  // ── Icons / tooltips ───────────────────────────────────────────────────────
  protected iconFor(a: AccessState): string {
    if (isPublic(a)) return 'public';
    if (a.users.length === 0 && a.roles.length === 0) return 'lock';
    return 'badge';
  }

  protected classFor(a: AccessState): string {
    if (isPublic(a)) return 'public';
    if (a.users.length === 0 && a.roles.length === 0) return 'authenticated';
    return 'roles';
  }

  protected tipFor(a: AccessState): string {
    if (isPublic(a)) return $localize`:@@Access_public:Public`;
    const parts: string[] = [];
    if (a.users.length) parts.push($localize`:@@Users:Users` + ': ' + a.users.join(', '));
    if (a.roles.length) parts.push($localize`:@@Roles:Roles` + ': ' + a.roles.join(', '));
    return parts.length ? parts.join(' · ') : $localize`:@@Authenticated:Authenticated`;
  }

  // ── Save ───────────────────────────────────────────────────────────────────
  protected async save(): Promise<void> {
    const id = this.selectedId();
    if (!id) return;
    const endpoints: EndpointPolicy[] = [];
    for (const o of this.operations()) {
      const s = this.state()[opKey(o.method, o.path)];
      if (!s?.override) continue;
      endpoints.push(toPolicy(o.method, o.path, s.access));
    }
    endpoints.push(...this.extras());
    const route = this.routeAccess();
    const security: EndpointSecurity = { endpoints };
    if (!isPublic(route)) {
      security.route = {
        ...(route.authenticated ? { authenticated: true } : {}),
        ...(route.users.length ? { users: route.users } : {}),
        ...(route.roles.length ? { roles: route.roles } : {}),
      };
    }

    this.saving.set(true);
    try {
      await firstValueFrom(this.api.saveRouteSecurity(id, security));
      this.snack.open(
        $localize`:@@Endpoint_security_saved:Endpoint security saved and applied`,
        undefined,
        { duration: 2500 },
      );
    } catch (e) {
      this.snack.open(this.message(e), undefined, { duration: 4000 });
    } finally {
      this.saving.set(false);
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
