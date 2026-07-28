import { Component, computed, inject, signal } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { MatButtonModule } from '@angular/material/button';
import { MatDialog } from '@angular/material/dialog';
import { MatIconModule, MatIconRegistry } from '@angular/material/icon';
import { MatSnackBar } from '@angular/material/snack-bar';
import { NavigationEnd, Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import {
  RailnavComponent,
  RailnavContainerComponent,
  RailnavContentComponent,
  RailnavItemComponent,
  RailnavSpacerComponent,
} from '@softwarity/rail-nav';
import { catchError, filter, firstValueFrom, map, of } from 'rxjs';
import { ApiService, Tenant } from './api.service';
import { TenantDialogComponent, TenantDialogResult } from './identity/tenant-dialog.component';
import { MeService } from './me.service';
import { UserMenuComponent } from './shared/user-menu.component';

// Console scopes (CONSOLE-01): Application (the product — identity, RBAC, theme,
// config), Tenants (drill into one org's options), Gateway (routing, vault, SSL).
// Each is a rail item opening a contextual drawer. Routes are lazy — moving an
// entry between drawers is just moving a link.
@Component({
  selector: 'app-root',
  imports: [
    RouterOutlet,
    RouterLink,
    RouterLinkActive,
    MatButtonModule,
    MatIconModule,
    RailnavComponent,
    RailnavContainerComponent,
    RailnavContentComponent,
    RailnavItemComponent,
    RailnavSpacerComponent,
    UserMenuComponent,
  ],
  styles: [
    `
      rail-nav-container {
        height: 100vh;
      }
      rail-nav-content {
        overflow: auto;
      }
      /* Entries inside a contextual drawer — a nav-list of links. */
      .drawer-item {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 10px 14px;
        border-radius: 999px;
        color: var(--mat-sys-on-surface);
        text-decoration: none;
        white-space: nowrap;
      }
      .drawer-item:hover {
        background: var(--mat-sys-surface-container-high);
      }
      .drawer-item.active {
        background: var(--mat-sys-secondary-container);
        color: var(--mat-sys-on-secondary-container);
      }
      .drawer-item.disabled {
        opacity: 0.45;
        cursor: default;
        pointer-events: none;
      }
      .drawer-item mat-icon {
        flex-shrink: 0;
      }
      /* a real button leading the drawer (creation), not a nav entry */
      .drawer-action {
        width: calc(100% - 28px);
        margin: 4px 14px 12px;
      }
      /* two-line entries: name over a muted, truncated description */
      .drawer-lines {
        display: flex;
        flex-direction: column;
        min-width: 0;
      }
      .drawer-desc {
        font-size: 0.75rem;
        color: var(--mat-sys-on-surface-variant);
        max-width: 190px;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .drawer-empty {
        padding: 10px 14px;
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.85rem;
      }
    `,
  ],
  template: `
    <rail-nav-container>
      <rail-nav title="meerkat" subtitle="console">
        <rail-nav-item
          i18n-label="@@Infra"
          label="Infra"
          routerLink="/infra"
          [active]="inInfra()"
          any-role="root infra-admin"
        >
          <mat-icon>dns</mat-icon>
        </rail-nav-item>
        <rail-nav-item
          i18n-label="@@Application"
          label="Application"
          routerLink="/application"
          [active]="inApp()"
          any-role="root app-admin"
        >
          <mat-icon>tune</mat-icon>
        </rail-nav-item>
        <rail-nav-item
          i18n-label="@@Tenants"
          label="Tenants"
          [for]="tenantsDrawer"
          [active]="inTenants()"
          (click)="openTenants()"
          any-role="root tenant-admin tenant-creator"
        >
          <mat-icon>domain</mat-icon>
        </rail-nav-item>
        <rail-nav-item
          i18n-label="@@Audit"
          label="Audit"
          routerLink="/audit"
          [active]="inAudit()"
          any-role="root gateway-admin app-admin tenant-admin"
        >
          <mat-icon>history_edu</mat-icon>
        </rail-nav-item>
        <rail-nav-spacer />
        <app-user-menu />
      </rail-nav>
      <rail-nav-content>
        <router-outlet />
      </rail-nav-content>
    </rail-nav-container>

    <!-- Application: the integrator's product — its people, roles, look, config.
         Tenants have their own rail entry; no list page needed here. -->
    <ng-template #appDrawer>
      <a routerLink="/general" routerLinkActive="active" class="drawer-item">
        <mat-icon>tune</mat-icon>
        <span i18n="@@Section_general">General</span>
      </a>
      <a routerLink="/locales" routerLinkActive="active" class="drawer-item">
        <mat-icon>translate</mat-icon>
        <span i18n="@@Locales">Locales</span>
      </a>
      <a routerLink="/roles" routerLinkActive="active" class="drawer-item">
        <mat-icon>badge</mat-icon>
        <span i18n="@@Roles">Roles</span>
      </a>
      <a routerLink="/users" routerLinkActive="active" class="drawer-item">
        <mat-icon>group</mat-icon>
        <span i18n="@@Users">Users</span>
      </a>
      <a routerLink="/security" routerLinkActive="active" class="drawer-item">
        <mat-icon>shield</mat-icon>
        <span i18n="@@Security">Security</span>
      </a>
    </ng-template>

    <!-- Tenants: drill into a single org's options (members, hours, TTL…).
         Creation happens right here — there is no tenant list page. -->
    <ng-template #tenantsDrawer>
      <button matButton="tonal" class="drawer-action" (click)="createTenant()" any-role="root tenant-creator">
        <mat-icon>add</mat-icon>
        <ng-container i18n="@@New_tenant">New tenant</ng-container>
      </button>
      @for (t of tenants(); track t.id) {
        <a [routerLink]="['/tenants', t.id]" routerLinkActive="active" class="drawer-item">
          <mat-icon>domain</mat-icon>
          <span class="drawer-lines">
            <span>{{ t.name }}</span>
            @if (t.description) {
              <span class="drawer-desc">{{ t.description }}</span>
            }
          </span>
        </a>
      } @empty {
        <span class="drawer-empty" i18n="@@No_tenant_yet">No tenant yet</span>
      }
    </ng-template>

    <!-- Gateway: the routing plane. -->
    <ng-template #gatewayDrawer>
      <a routerLink="/routes" routerLinkActive="active" class="drawer-item">
        <mat-icon>alt_route</mat-icon>
        <span i18n="@@Routes">Routes</span>
      </a>
      <a routerLink="/theme" routerLinkActive="active" class="drawer-item">
        <mat-icon>web</mat-icon>
        <span i18n="@@Built_in_pages">Built-in pages</span>
      </a>
      <a routerLink="/endpoint-security" routerLinkActive="active" class="drawer-item">
        <mat-icon>security</mat-icon>
        <span i18n="@@Endpoint_security">Endpoint security</span>
      </a>
      <a routerLink="/access-tokens" routerLinkActive="active" class="drawer-item" any-role="root">
        <mat-icon>key</mat-icon>
        <span i18n="@@Access_tokens">Access tokens</span>
      </a>
    </ng-template>
  `,
})
export class AppComponent {
  private readonly api = inject(ApiService);
  private readonly router = inject(Router);
  private readonly dialog = inject(MatDialog);
  private readonly snack = inject(MatSnackBar);

  // Tenants for the Tenants drawer — scoped by the API (root: all; admin:
  // theirs). Reloaded after a creation from the drawer.
  protected readonly tenants = signal<Tenant[]>([]);

  private loadTenants(): void {
    this.api
      .listTenants()
      .pipe(catchError(() => of<Tenant[]>([])))
      .subscribe((tenants) => this.tenants.set(tenants));
  }

  protected async createTenant(): Promise<void> {
    const res = await firstValueFrom(
      this.dialog
        .open<TenantDialogComponent, void, TenantDialogResult | undefined>(TenantDialogComponent, {
          width: '480px',
          restoreFocus: true,
        })
        .afterClosed(),
    );
    if (!res) return;
    this.api.createTenant({ name: res.name, description: res.description }).subscribe({
      next: (t) => {
        this.loadTenants();
        void this.router.navigate(['/tenants', t.id]);
      },
      error: (err) => {
        const e = err as { error?: { error?: string } };
        this.snack.open(
          typeof e?.error?.error === 'string' ? e.error.error : $localize`:@@Request_failed:Request failed`,
          undefined,
          { duration: 4000 },
        );
      },
    });
  }

  private readonly url = toSignal(
    this.router.events.pipe(
      filter((e) => e instanceof NavigationEnd),
      map(() => this.router.url),
    ),
    { initialValue: this.router.url },
  );
  protected readonly inApp = computed(() => {
    const u = this.url();
    return (
      u.startsWith('/general') ||
      u.startsWith('/locales') ||
      u.startsWith('/users') ||
      u.startsWith('/security') ||
      u.startsWith('/roles')
    );
  });
  protected readonly inTenants = computed(() => /^\/tenants\/[^/]+/.test(this.url()));
  protected readonly inGateway = computed(
    () =>
      this.url().startsWith('/routes') ||
      this.url().startsWith('/theme') ||
      this.url().startsWith('/endpoint-security') ||
      this.url().startsWith('/access-tokens'),
  );
  // Audit is a transverse section of its own (not under Application): it scopes
  // itself server-side to the caller's domains (gateway/app/tenant).
  protected readonly inAudit = computed(() => this.url().startsWith('/audit'));

  constructor() {
    inject(MatIconRegistry).setDefaultFontSetClass('material-symbols-outlined');
    // Role-based UI visibility (styles/_roles.scss): MeService loads /api/me and
    // mirrors the user's capabilities and tenant-admin status as classes on
    // <body>; `any-role="…"` elements show accordingly.
    inject(MeService).ensureLoaded();
    this.loadTenants();
  }

  protected go(url: string): void {
    void this.router.navigate([url]);
  }

  // Clicking "Tenants" lands on the first org's options; the drawer lists the rest.
  protected openTenants(): void {
    this.loadTenants(); // freshly edited names/descriptions show up right away
    const first = this.tenants()[0];
    if (first) void this.router.navigate(['/tenants', first.id]);
  }

}
