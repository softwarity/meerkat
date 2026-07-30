import { Component, computed, inject, signal } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatSidenavModule } from '@angular/material/sidenav';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { MatTooltipModule } from '@angular/material/tooltip';
import { ActivatedRoute, Router } from '@angular/router';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import { ApiService, AuthProvider } from '../../api.service';
import { AuthProviderEditorComponent } from './auth-provider-editor.component';

// External authentication (AUTH-19), infra plane: the authorities people may
// sign in through. A directory or an identity provider is a third-party
// service reached by URL, with credentials, exactly like a route's upstream.
// What it grants once someone is in stays the application's business: a first
// sign-in creates an account that reaches nothing until an admin places it.
@Component({
  selector: 'app-auth-providers-page',
  imports: [
    MatButtonModule,
    MatIconModule,
    MatSidenavModule,
    MatTableModule,
    MatTooltipModule,
    LoadingIndicatorComponent,
    AuthProviderEditorComponent,
  ],
  templateUrl: './auth-providers-page.component.html',
  styleUrl: './auth-providers-page.component.scss',
})
export class AuthProvidersPageComponent {
  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);
  private readonly router = inject(Router);
  private readonly ar = inject(ActivatedRoute);

  protected readonly loading = signal(true);
  protected readonly providers = signal<AuthProvider[]>([]);
  protected readonly columns = ['name', 'kind', 'target', 'state'];

  // The URL drives the drawer, like routes and roles.
  private readonly params = toSignal(this.ar.paramMap);
  private readonly urlSegs = toSignal(this.ar.url);
  protected readonly editing = computed<AuthProvider | 'new' | null>(() => {
    if (this.urlSegs()?.some((s) => s.path === 'new')) return 'new';
    const id = this.params()?.get('id');
    if (!id) return null;
    return this.providers().find((p) => p.id === id) ?? null;
  });
  protected readonly editingProvider = computed(() => {
    const e = this.editing();
    return e === null || e === 'new' ? null : e;
  });

  constructor() {
    this.load();
  }

  load(): void {
    this.loading.set(true);
    this.api.authProviders().subscribe({
      next: (list) => {
        this.providers.set(list);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  // What an authority points at, in one line: the issuer, or the server.
  protected target(p: AuthProvider): string {
    const cfg = p.config ?? {};
    // GitHub has no address to show: what identifies the setup is the
    // organisation it lets in.
    if (p.kind === 'github') {
      const orgs = cfg['allowedOrgs'];
      return Array.isArray(orgs) && orgs.length ? orgs.join(', ') : 'github.com';
    }
    return String(cfg['issuer'] ?? cfg['url'] ?? '');
  }

  protected kindLabel(p: AuthProvider): string {
    switch (p.kind) {
      case 'oidc':
        return 'OpenID Connect';
      case 'ldap':
        return String(p.config?.['dialect'] ?? '') === 'ad'
          ? 'Active Directory'
          : $localize`:@@Kind_directory:Directory`;
      case 'github':
        return 'GitHub';
      default:
        return 'SAML';
    }
  }

  protected open(p: AuthProvider): void {
    void this.router.navigate(['/infra/auth-providers', p.id]);
  }

  protected openNew(): void {
    void this.router.navigate(['/infra/auth-providers', 'new']);
  }

  protected closeEditor(): void {
    if (this.editing() !== null) void this.router.navigate(['/infra/auth-providers']);
  }

  protected onSaved(saved: AuthProvider): void {
    this.snack.open($localize`:@@Provider_NAME_saved:Authority "${saved.name}:NAME:" saved`, undefined, {
      duration: 2500,
    });
    if (this.editing() === 'new') {
      void this.router.navigate(['/infra/auth-providers', saved.id], { replaceUrl: true });
    }
    this.load();
  }

  protected onDeleted(): void {
    void this.router.navigate(['/infra/auth-providers']);
    this.load();
  }
}
