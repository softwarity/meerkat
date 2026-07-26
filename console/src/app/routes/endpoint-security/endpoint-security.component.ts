import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatSelectModule } from '@angular/material/select';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatSnackBar } from '@angular/material/snack-bar';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import {
  ApiService,
  EndpointAccess,
  EndpointPolicy,
  EndpointSecurity,
  OpenAPIOperation,
  Role,
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

// Endpoint security editor (RBAC-07): a swagger-ui-like listing of a route's
// OpenAPI operations, each given an access rule. The spec is fetched and parsed
// SERVER-SIDE (Swagger 2.0 or OpenAPI 3.x), so this screen only ever sees a
// flat operation list. Saving PUTs the assembled security to the admin API,
// which validates by compiling and reloads the data plane (saving IS applying).
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
  ],
  templateUrl: './endpoint-security.component.html',
  styleUrl: './endpoint-security.component.scss',
})
export class EndpointSecurityComponent {
  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);
  protected readonly routeId = inject(ActivatedRoute).snapshot.paramMap.get('id') ?? '';

  protected readonly loading = signal(true);
  protected readonly saving = signal(false);
  protected readonly error = signal('');
  protected readonly data = signal<RouteOperations | null>(null);
  protected readonly roles = signal<Role[]>([]);

  protected readonly denyByDefault = signal(false);
  // Per-operation edits, keyed by opKey.
  private readonly state = signal<Record<string, OpState>>({});
  // Saved policies that match no listed operation (wildcards, endpoints since
  // removed upstream): kept aside so a save never silently drops policy.
  private readonly extras = signal<EndpointPolicy[]>([]);

  // Operations grouped by their first tag, tags alphabetical, untagged last.
  protected readonly groups = computed(() => {
    const ops = this.data()?.operations ?? [];
    const byTag = new Map<string, OpenAPIOperation[]>();
    for (const o of ops) {
      const tag = o.tags?.[0] ?? '';
      const list = byTag.get(tag);
      if (list) list.push(o);
      else byTag.set(tag, [o]);
    }
    return [...byTag.entries()]
      .sort((a, b) => (a[0] === '' ? 1 : b[0] === '' ? -1 : a[0].localeCompare(b[0])))
      .map(([tag, operations]) => ({ tag, operations }));
  });

  // Count of operations carrying an explicit rule, plus the preserved extras.
  protected readonly securedCount = computed(() => {
    const st = this.state();
    let n = this.extras().length;
    for (const k of Object.keys(st)) if (st[k].access !== 'default') n++;
    return n;
  });

  constructor() {
    void this.load();
  }

  private async load(): Promise<void> {
    if (!this.routeId) {
      this.error.set($localize`:@@No_route_selected:No route selected`);
      this.loading.set(false);
      return;
    }
    this.loading.set(true);
    this.error.set('');
    try {
      const [ops, roles] = await Promise.all([
        firstValueFrom(this.api.getRouteOperations(this.routeId)),
        firstValueFrom(this.api.listRoles()),
      ]);
      this.roles.set(roles);
      this.seed(ops);
      this.data.set(ops);
    } catch (e) {
      this.error.set(this.message(e));
    } finally {
      this.loading.set(false);
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

  protected stateOf(o: OpenAPIOperation): OpState {
    return this.state()[opKey(o.method, o.path)] ?? { access: 'default', roles: [] };
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
    if (!this.routeId) return;
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
      await firstValueFrom(this.api.saveRouteSecurity(this.routeId, security));
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
