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
import { firstValueFrom } from 'rxjs';
import {
  ApiService,
  EndpointAccess,
  EndpointPolicy,
  EndpointSecurity,
  OpenAPIOperation,
  Role,
  Route,
  RouteOperations,
} from '../../api.service';

// Editable per-operation state. 'default' means no explicit rule: the operation
// then follows deny-by-default (refused) or, without it, falls through open.
type Access = 'default' | EndpointAccess;
interface OpState {
  access: Access;
  roles: string[];
}

// Stable key for an operation: upper-case verb + path.
function opKey(method: string, path: string): string {
  return `${method.toUpperCase()} ${path}`;
}

// Endpoint security (RBAC-07): a dedicated Gateway page. Pick a route that
// exposes an OpenAPI spec, and its operations load as a table (sticky header,
// scrolling rows, global Save in the footer). A row shows the method, path,
// description and an access icon; clicking it expands an inline editor. The
// spec is fetched and parsed SERVER-SIDE, so this screen only ever sees a flat
// operation list. Saving PUTs the assembled security to the admin API, which
// validates by compiling and reloads the data plane (saving IS applying).
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
  protected readonly selectedId = signal('');
  protected readonly data = signal<RouteOperations | null>(null);

  protected readonly denyByDefault = signal(false);
  // Per-operation edits, keyed by opKey.
  private readonly state = signal<Record<string, OpState>>({});
  // Saved policies that match no listed operation (wildcards, endpoints since
  // removed upstream): kept aside so a save never silently drops policy.
  private readonly extras = signal<EndpointPolicy[]>([]);
  // Which rows are expanded (opKey set).
  private readonly expanded = signal<Set<string>>(new Set());

  // The routes that expose an OpenAPI spec are the ones that can be secured
  // per endpoint; the selector lists exactly those.
  protected readonly apiRoutes = computed(() => this.routes().filter((r) => !!r.api?.swaggerUrl));

  // Flat operation list backing the table.
  protected readonly operations = computed(() => this.data()?.operations ?? []);
  protected readonly columns = ['status', 'method', 'path', 'summary', 'expand'];

  // Count of operations carrying an explicit rule, plus the preserved extras.
  protected readonly securedCount = computed(() => {
    const st = this.state();
    let n = this.extras().length;
    for (const k of Object.keys(st)) if (st[k].access !== 'default') n++;
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
      const [routes, roles] = await Promise.all([
        firstValueFrom(this.api.listRoutes()),
        firstValueFrom(this.api.listRoles()),
      ]);
      this.roles.set(roles);
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
    this.denyByDefault.set(!!sec.denyByDefault);
    const saved = new Map<string, EndpointPolicy>();
    for (const e of sec.endpoints ?? []) saved.set(opKey(e.method, e.path), e);

    const st: Record<string, OpState> = {};
    const matched = new Set<string>();
    for (const o of ops.operations) {
      const k = opKey(o.method, o.path);
      const p = saved.get(k);
      if (p) {
        st[k] = { access: p.access, roles: p.roles ?? [] };
        matched.add(k);
      } else {
        st[k] = { access: 'default', roles: [] };
      }
    }
    this.state.set(st);
    this.extras.set((sec.endpoints ?? []).filter((e) => !matched.has(opKey(e.method, e.path))));
  }

  // Expand / collapse a row. mat-table only re-evaluates the detail-row
  // predicate on renderRows, so nudge it (state/cell content stay reactive on
  // their own).
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

  // Row predicate: a detail row exists only under an expanded operation.
  protected readonly isDetailRow = (_: number, o: OpenAPIOperation): boolean => this.isExpanded(o);

  protected stateOf(o: OpenAPIOperation): OpState {
    return this.state()[opKey(o.method, o.path)] ?? { access: 'default', roles: [] };
  }

  protected accessIcon(o: OpenAPIOperation): string {
    switch (this.stateOf(o).access) {
      case 'public':
        return 'public';
      case 'authenticated':
        return 'lock';
      case 'roles':
        return 'badge';
      default:
        return 'radio_button_unchecked';
    }
  }

  protected accessTip(o: OpenAPIOperation): string {
    const s = this.stateOf(o);
    switch (s.access) {
      case 'public':
        return $localize`:@@Access_public:Public`;
      case 'authenticated':
        return $localize`:@@Access_authenticated:Authenticated`;
      case 'roles':
        return $localize`:@@Access_roles:Roles` + (s.roles.length ? ': ' + s.roles.join(', ') : '');
      default:
        return $localize`:@@Access_default:Default`;
    }
  }

  protected setAccess(o: OpenAPIOperation, access: Access): void {
    const k = opKey(o.method, o.path);
    this.state.update((s) => ({ ...s, [k]: { ...(s[k] ?? { access: 'default', roles: [] }), access } }));
  }

  protected setRoles(o: OpenAPIOperation, roles: string[]): void {
    const k = opKey(o.method, o.path);
    this.state.update((s) => ({ ...s, [k]: { ...(s[k] ?? { access: 'default', roles: [] }), roles } }));
  }

  protected async save(): Promise<void> {
    const id = this.selectedId();
    if (!id) return;
    const endpoints: EndpointPolicy[] = [];
    for (const o of this.data()?.operations ?? []) {
      const s = this.state()[opKey(o.method, o.path)];
      if (!s || s.access === 'default') continue;
      const ep: EndpointPolicy = { method: o.method.toUpperCase(), path: o.path, access: s.access };
      if (s.access === 'roles') ep.roles = s.roles;
      endpoints.push(ep);
    }
    endpoints.push(...this.extras());
    const security: EndpointSecurity = { denyByDefault: this.denyByDefault(), endpoints };

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
