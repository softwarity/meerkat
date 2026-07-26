import { Service, computed, inject, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { ApiService, Me, User } from './api.service';

// Session identity. The gateway STAMPS it on <body> when it serves the
// console (capability roles as classes, data-meerkat-* attributes): reading
// the stamp replaces the /api/me boot call, and the role-CSS visibility
// (`any-role` in styles/_roles.scss) applies from the first paint. /api/me
// stays as the fallback when the stamp is absent (bare `ng serve`). Guards
// await the load either way; the API enforces the same scopes server-side.
@Service()
export class MeService {
  private readonly api = inject(ApiService);

  readonly me = signal<Me | null>(null);
  readonly user = computed(() => this.me()?.user ?? null);
  readonly isRoot = computed(() => this.user()?.root ?? false);
  readonly isTenantCreator = computed(() => this.user()?.tenantCreator ?? false);
  // Split administration (RBAC-05): root implies both scopes.
  readonly isGatewayAdmin = computed(() => this.isRoot() || (this.user()?.gatewayAdmin ?? false));
  readonly isAppAdmin = computed(() => this.isRoot() || (this.user()?.appAdmin ?? false));
  // Administers at least one tenant (owner or ADMIN), computed server-side and
  // carried on /api/me (a non-member owner would be missed by the memberships).
  readonly isTenantAdmin = computed(() => this.isRoot() || (this.me()?.tenantAdmin ?? false));

  private loading?: Promise<Me | null>;

  // Resolves the identity once (cached); safe to call from guards and the
  // app shell.
  ensureLoaded(): Promise<Me | null> {
    if (!this.loading) {
      const stamped = this.fromStamp();
      if (stamped) {
        this.me.set(stamped);
        this.loading = Promise.resolve(stamped);
      } else {
        this.loading = firstValueFrom(this.api.me())
          .then((me) => {
            this.apply(me);
            return me;
          })
          .catch(() => {
            this.me.set(null);
            return null;
          });
      }
    }
    return this.loading;
  }

  // The server stamp: the username attribute marks a signed-in session; the
  // role classes are already on <body>, nothing to mirror.
  private fromStamp(): Me | null {
    const b = document.body;
    const username = b.getAttribute('data-meerkat-username');
    if (!username) return null;
    const has = (c: string) => b.classList.contains(c);
    const user = {
      id: b.getAttribute('data-meerkat-user-id') ?? '',
      username,
      fullname: b.getAttribute('data-meerkat-fullname') ?? '',
      email: b.getAttribute('data-meerkat-email') ?? '',
      root: has('root'),
      dev: has('dev'),
      tester: has('tester'),
      tenantCreator: has('tenant-creator'),
      gatewayAdmin: has('gateway-admin'),
      appAdmin: has('app-admin'),
    } as User;
    return { user, tenants: [] };
  }

  private apply(me: Me): void {
    this.me.set(me);
    const roles: string[] = [];
    if (me.user.root) roles.push('root');
    if (me.user.dev) roles.push('dev');
    if (me.user.tester) roles.push('tester');
    if (me.user.tenantCreator) roles.push('tenant-creator');
    if (me.user.gatewayAdmin) roles.push('gateway-admin');
    if (me.user.appAdmin) roles.push('app-admin');
    // Ownership is decoupled from membership, so the server computes this
    // (owner-or-admin of any tenant) — the memberships list alone can miss a
    // non-member owner.
    if (me.tenantAdmin) roles.push('tenant-admin');
    document.body.classList.remove(
      'root',
      'dev',
      'tester',
      'tenant-creator',
      'gateway-admin',
      'app-admin',
      'tenant-admin',
    );
    document.body.classList.add(...roles);
  }
}
