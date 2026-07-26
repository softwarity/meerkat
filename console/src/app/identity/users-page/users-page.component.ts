import { Component, computed, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatDialog } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';
import { MatSidenavModule } from '@angular/material/sidenav';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { MatTooltipModule } from '@angular/material/tooltip';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import { forkJoin } from 'rxjs';
import { ApiService, Settings, User } from '../../api.service';
import { MeService } from '../../me.service';
import { PasswordDialogComponent } from '../password-dialog.component';
import { UserDialogComponent } from '../user-dialog.component';
import { UserEditorComponent } from '../user-editor/user-editor.component';

// mfaText renders the resolved global second-factor policy — the label a user's
// "Inherited" resolves to (the user record sits directly under global).
function mfaText(required: boolean): string {
  return required ? $localize`:@@MFA_required:Required` : $localize`:@@MFA_optional:Optional`;
}

// Users administration — root scope. The table is a plain list; clicking a row
// opens the user's options in a right drawer (the same pattern as routes).
@Component({
  selector: 'app-users-page',
  imports: [
    MatButtonModule,
    MatIconModule,
    MatSidenavModule,
    MatTableModule,
    MatTooltipModule,
    LoadingIndicatorComponent,
    UserEditorComponent,
  ],
  templateUrl: './users-page.component.html',
  styleUrl: './users-page.component.scss',
})
export class UsersPageComponent {
  private readonly api = inject(ApiService);
  private readonly dialog = inject(MatDialog);
  private readonly me = inject(MeService);
  private readonly snack = inject(MatSnackBar);

  protected readonly loading = signal(true);
  protected readonly users = signal<User[]>([]);
  private readonly settings = signal<Settings | null>(null);
  protected readonly columns = ['identity', 'summary'];

  // null = drawer closed, a User = editing that one.
  protected readonly editing = signal<User | null>(null);
  protected readonly globalMfaLabel = computed(() => mfaText(!!this.settings()?.mfaRequired));

  protected meId(): string {
    return this.me.user()?.id ?? '';
  }

  constructor() {
    this.load();
  }

  private load(): void {
    this.loading.set(true);
    forkJoin({ users: this.api.listUsers(), settings: this.api.settings() }).subscribe({
      next: ({ users, settings }) => {
        this.users.set(users);
        this.settings.set(settings);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  protected create(): void {
    this.dialog
      .open(UserDialogComponent, { width: '480px' })
      .afterClosed()
      .subscribe((created?: { user: User; password: string }) => {
        if (!created) return;
        this.dialog.open(PasswordDialogComponent, {
          data: { username: created.user.username, password: created.password },
        });
        this.load();
      });
  }

  // A field changed in the drawer: refresh the row AND keep the drawer bound to
  // the fresh user so its toggles reflect server truth.
  protected onUserSaved(fresh: User): void {
    this.users.update((list) => list.map((u) => (u.id === fresh.id ? fresh : u)));
    this.editing.set(fresh);
  }

  protected onClose(): void {
    this.editing.set(null);
    this.load();
  }

  // The superpowers (RBAC-05), as clickable badges on the row.
  protected readonly capabilities = [
    {
      key: 'root' as const,
      label: 'root',
      tooltip: $localize`:@@Tooltip_root:Administers the whole gateway: routes, users, tenants, settings`,
    },
    {
      key: 'gatewayAdmin' as const,
      label: $localize`:@@gateway_admin:gateway admin`,
      tooltip: $localize`:@@Tooltip_gateway_admin:Administers the routing plane: routes and the built-in pages`,
    },
    {
      key: 'appAdmin' as const,
      label: $localize`:@@app_admin:app admin`,
      tooltip: $localize`:@@Tooltip_app_admin:Administers the application identity: users, roles, settings`,
    },
    {
      key: 'dev' as const,
      label: 'dev',
      tooltip: $localize`:@@Tooltip_dev:Unlocks the developer tooling: dev keys, service substitution (plug)`,
    },
    {
      key: 'tester' as const,
      label: 'tester',
      tooltip: $localize`:@@Tooltip_tester:Can opt into a developer's variant of the application`,
    },
    {
      key: 'tenantCreator' as const,
      label: $localize`:@@tenant_creator:tenant creator`,
      tooltip: $localize`:@@Tooltip_tenant_creator:May create tenants, and owns the tenants they create`,
    },
  ];

  protected toggleCapability(
    u: User,
    key: 'root' | 'dev' | 'tester' | 'tenantCreator' | 'gatewayAdmin' | 'appAdmin',
    event: Event,
  ): void {
    event.stopPropagation(); // the row click opens the drawer — not this
    this.api.updateUser({ ...u, [key]: !u[key] }).subscribe({
      next: (fresh) => this.users.update((list) => list.map((x) => (x.id === fresh.id ? fresh : x))),
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
}
