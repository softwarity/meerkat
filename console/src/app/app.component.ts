import { Component, computed, inject, signal } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { MatButtonModule } from '@angular/material/button';
import { MatDialog } from '@angular/material/dialog';
import { MatIconModule, MatIconRegistry } from '@angular/material/icon';
import { MatSnackBar } from '@angular/material/snack-bar';
import { DomSanitizer } from '@angular/platform-browser';
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

// Console scopes (CONSOLE-01): Infra (routing, relay, tokens), Application (the
// product — identity, RBAC, built-in pages), Tenants (drill into one org), plus
// the transverse screens (API, Vault, Audit). Each is a rail item; the two fixed
// planes are URL prefixes (/infra, /application) whose sections live in a left
// nav inside the page, the shape a tenant already had. Only Tenants still opens
// a drawer, because its entries are data.
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
  styleUrl: './app.component.scss',
  templateUrl: './app.component.html',
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
    this.api
      .createTenant({
        name: res.name,
        description: res.description,
        groupMode: res.groupMode,
      })
      .subscribe({
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
  // A plane is a URL PREFIX now (/infra/…, /application/…), so "which rail entry
  // is active" is one startsWith, not a list of section names to keep in sync.
  protected readonly inApp = computed(() => this.url().startsWith('/application'));
  protected readonly inTenants = computed(() => /^\/tenants\/[^/]+/.test(this.url()));
  protected readonly inInfra = computed(() => this.url().startsWith('/infra'));
  // Audit is a transverse section of its own (not under Application): it scopes
  // itself server-side to the caller's domains (gateway/app/tenant).
  protected readonly inVault = computed(() => this.url().startsWith('/vault'));
  protected readonly inAudit = computed(() => this.url().startsWith('/audit'));
  protected readonly inIssues = computed(() => this.url().startsWith('/issues'));
  protected readonly inApiDocs = computed(() => this.url().startsWith('/api'));

  constructor() {
    const icons = inject(MatIconRegistry);
    icons.setDefaultFontSetClass('material-symbols-outlined');
    // Brand SVG logos from public/, usable as <mat-icon svgIcon="jwt|openapi|swagger-ui">.
    const sanitizer = inject(DomSanitizer);
    for (const name of ['jwt', 'openapi', 'swagger-ui']) {
      icons.addSvgIcon(name, sanitizer.bypassSecurityTrustResourceUrl(`${name}.svg`));
    }
    // Role-based UI visibility (styles/_roles.scss): MeService loads /api/me and
    // mirrors the user's capabilities and tenant-admin status as classes on
    // <body>; `any-role="…"` elements show accordingly.
    inject(MeService).ensureLoaded();
    this.loadTenants();
  }

  // Clicking "Tenants" lands on the first org's options; the drawer lists the rest.
  protected openTenants(): void {
    this.loadTenants(); // freshly edited names/descriptions show up right away
    const first = this.tenants()[0];
    if (first) void this.router.navigate(['/tenants', first.id]);
  }
}
