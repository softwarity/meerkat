import { Component, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatSnackBar } from '@angular/material/snack-bar';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import { ApiService, BusinessAccess, Settings } from '../api.service';
import { BusinessAccessFormComponent } from '../identity/business-access-form.component';

// Application-level General settings (root only): the GLOBAL working hours, the
// value every tenant inherits unless it overrides. A full PUT of /api/settings —
// the other fields ride along. Two things are deliberately NOT here: the group
// mode (RBAC-03), a per-tenant call, and the session TTL, which is a security
// policy and lives on the Security page.
@Component({
  selector: 'app-general-page',
  imports: [
    MatButtonModule,
    MatCardModule,
    LoadingIndicatorComponent,
    BusinessAccessFormComponent,
  ],
  styles: [
    `
      .banner {
        display: flex;
        align-items: center;
        gap: 16px;
        padding: 12px 24px;
      }
      .banner h1 {
        font-size: 1.15rem;
        font-weight: 500;
        margin: 0;
        flex: 1;
      }
      .content {
        padding: 0 24px 24px;
        display: grid;
        gap: 16px;
        max-width: 720px;
      }
      mat-card {
        padding: 16px 20px;
      }
      h3 {
        margin: 0 0 6px;
        font-size: 0.95rem;
        font-weight: 500;
      }
      .hint {
        margin: 0 0 12px;
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.85rem;
      }
      .actions {
        display: flex;
        justify-content: flex-end;
      }
    `,
  ],
  template: `
    @if (loading()) {
      <loading-indicator withContainer />
    } @else {
      <div class="banner">
        <h1 i18n="@@Section_general">General</h1>
      </div>

      <div class="content">
        <mat-card appearance="outlined">
          <h3 i18n="@@Working_hours">Working hours</h3>
          <p class="hint" i18n="@@Working_hours_global_hint">
            The application-wide access window: every tenant inherits it unless it defines its own.
          </p>
          <app-business-access-form
            [value]="businessAccess()"
            [topLevel]="true"
            (valueChange)="businessAccess.set($event)"
          />
        </mat-card>

        <div class="actions">
          <button matButton="filled" (click)="save()" [disabled]="saving()" i18n="@@Save">Save</button>
        </div>
      </div>
    }
  `,
})
export class GeneralPageComponent {
  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);

  protected readonly loading = signal(true);
  protected readonly saving = signal(false);
  private readonly settings = signal<Settings | null>(null);

  protected readonly businessAccess = signal<BusinessAccess>({ inherited: false });

  constructor() {
    this.api.settings().subscribe({
      next: (s) => {
        this.settings.set(s);
        this.businessAccess.set(s.businessAccess ?? { inherited: false });
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  protected save(): void {
    const s = this.settings();
    if (!s) return;
    this.saving.set(true);
    this.api
      .saveSettings({
        ...s,
        businessAccess: { ...this.businessAccess(), inherited: false },
      })
      .subscribe({
        next: (saved) => {
          this.settings.set(saved);
          this.saving.set(false);
          this.snack.open($localize`:@@Settings_saved:Settings saved`, undefined, { duration: 2500 });
        },
        error: (err: unknown) => {
          this.saving.set(false);
          const e = err as { error?: { error?: string } };
          this.snack.open(
            typeof e?.error?.error === 'string' ? e.error.error : $localize`:@@Save_failed:Save failed`,
            undefined,
            { duration: 4000 },
          );
        },
      });
  }
}
