import { Component, computed, inject, LOCALE_ID, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatSnackBar } from '@angular/material/snack-bar';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import { ApiService, BusinessAccess, Settings } from '../api.service';
import { BusinessAccessFormComponent } from '../identity/business-access-form.component';
import { humanDuration } from '../shared/duration';

const TTL_CHOICES = ['PT15M', 'PT30M', 'PT1H', 'PT2H', 'PT4H', 'PT8H', 'PT12H', 'P1D'];

// Application-level General settings (root only): the GLOBAL working hours (the
// value every tenant inherits unless it overrides), the application-wide
// session TTL, and the group mode (RBAC-03: cumulative vs exclusive, tenant
// overridable). A full PUT of /api/settings — the other fields ride along.
@Component({
  selector: 'app-general-page',
  imports: [
    MatButtonModule,
    MatCardModule,
    MatFormFieldModule,
    MatSelectModule,
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
      .field {
        width: 280px;
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

        <mat-card appearance="outlined">
          <h3 i18n="@@Session_TTL">Session TTL</h3>
          <p class="hint" i18n="@@Session_TTL_hint">
            How long a session lives before the user must sign in again.
          </p>
          <mat-form-field class="field">
            <mat-label i18n="@@Session_TTL">Session TTL</mat-label>
            <mat-select [value]="sessionTTL()" (selectionChange)="sessionTTL.set($event.value)">
              @for (c of ttlChoices(); track c) {
                <mat-option [value]="c">{{ human(c) }}</mat-option>
              }
            </mat-select>
          </mat-form-field>
        </mat-card>

        <mat-card appearance="outlined">
          <h3 i18n="@@Group_mode">Group mode</h3>
          <p class="hint" i18n="@@Group_mode_hint">
            How a member's groups combine: cumulative merges the roles of every assigned group;
            exclusive makes the user pick ONE group at sign-in (and again after each tenant switch).
            Each tenant may override this.
          </p>
          <mat-form-field class="field">
            <mat-label i18n="@@Group_mode">Group mode</mat-label>
            <mat-select [value]="groupMode()" (selectionChange)="groupMode.set($event.value)">
              <mat-option value="MULTIPLE" i18n="@@Cumulative">Cumulative</mat-option>
              <mat-option value="SINGLE" i18n="@@Exclusive">Exclusive</mat-option>
            </mat-select>
          </mat-form-field>
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
  private readonly locale = inject(LOCALE_ID);

  protected readonly loading = signal(true);
  protected readonly saving = signal(false);
  private readonly settings = signal<Settings | null>(null);

  protected readonly businessAccess = signal<BusinessAccess>({ inherited: false });
  protected readonly sessionTTL = signal('');
  protected readonly groupMode = signal('MULTIPLE');

  // The preset list, plus whatever non-preset value the store already holds so
  // the select never loses it.
  protected readonly ttlChoices = computed(() => {
    const current = this.sessionTTL();
    return current && !TTL_CHOICES.includes(current) ? [current, ...TTL_CHOICES] : TTL_CHOICES;
  });

  protected human(iso: string): string {
    return humanDuration(iso, this.locale);
  }

  constructor() {
    this.api.settings().subscribe({
      next: (s) => {
        this.settings.set(s);
        this.businessAccess.set(s.businessAccess ?? { inherited: false });
        this.sessionTTL.set(s.sessionTTL);
        this.groupMode.set(s.groupMode || 'MULTIPLE');
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
        sessionTTL: this.sessionTTL().trim(),
        groupMode: this.groupMode(),
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
