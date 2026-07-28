import { DatePipe } from '@angular/common';
import { Component, computed, effect, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatSnackBar } from '@angular/material/snack-bar';
import { ApiService, BusinessAccess, Settings } from '../../api.service';
import { FormFieldComponent } from '../../shared/form-field.component';
import { BusinessAccessFormComponent } from '../business-access-form.component';
import { TenantScope } from '../tenant-scope';

// The tenant's General section (a child route of the tenant layout): identity
// and working hours, committed together with Save. The layout owns the tenant
// signal — a save pushes the fresh copy back so the left nav's name follows.
@Component({
  selector: 'app-tenant-general',
  imports: [
    DatePipe,
    MatButtonModule,
    MatFormFieldModule,
    MatInputModule,
    MatSelectModule,
    MatSlideToggleModule,
    FormFieldComponent,
    BusinessAccessFormComponent,
  ],
  styles: [
    `
      :host {
        display: flex;
        flex-direction: column;
        min-height: 100%;
      }
      .name-row {
        display: flex;
        align-items: center;
        gap: 20px;
        flex-wrap: wrap;
      }
      .name-field {
        width: min(420px, 100%);
      }
      .meta {
        margin: 2px 0 16px;
        font-size: 0.82rem;
        color: var(--mat-sys-on-surface-variant);
      }
      .meta .who {
        color: var(--mat-sys-on-surface);
        font-weight: 500;
      }
      .meta .muted {
        font-style: italic;
      }
      .desc-field {
        display: block;
        width: min(640px, 100%);
      }
      .hint {
        margin: 0 0 10px;
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.85rem;
      }
      .mode-field {
        width: 280px;
      }
      .sub {
        margin: 20px 0 10px;
        font-size: 0.78rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: var(--mat-sys-on-surface-variant);
      }
      footer {
        display: flex;
        justify-content: flex-end;
        margin-top: auto;
        padding-top: 16px;
      }
    `,
  ],
  template: `
    <div class="name-row">
      <app-form-field class="name-field" subscriptSizing="dynamic" i18n-label="@@Name" label="Name">
        <input matInput [value]="name()" (input)="name.set($any($event.target).value)" />
      </app-form-field>
      <mat-slide-toggle [checked]="enabled()" (change)="enabled.set($event.checked)">
        <ng-container i18n="@@Enabled">Enabled</ng-container>
      </mat-slide-toggle>
    </div>
    @if (scope.tenant(); as t) {
      <p class="meta">
        <span i18n="@@Created_on">Created on</span> {{ t.createdAt * 1000 | date: 'yyyy-MM-dd' }}
        @if (t.createdByName) {
          <span i18n="@@by">by</span> <span class="who">{{ t.createdByName }}</span>
        }
        @if (t.ownerName) {
          · <span i18n="@@Owner">Owner</span>: <span class="who">{{ t.ownerName }}</span>
        } @else {
          · <span class="muted" i18n="@@No_owner">no owner</span>
        }
      </p>
    }
    <app-form-field class="desc-field" i18n-label="@@Description" label="Description">
      <textarea
        matInput
        rows="2"
        [value]="description()"
        (input)="description.set($any($event.target).value)"
      ></textarea>
    </app-form-field>

    <h3 class="sub" i18n="@@Group_mode">Group mode</h3>
    <p class="hint" i18n="@@Tenant_group_mode_hint">
      Cumulative merges the roles of every assigned group; exclusive makes members pick ONE group
      when they enter this tenant.
    </p>
    <mat-form-field class="mode-field">
      <mat-label i18n="@@Group_mode">Group mode</mat-label>
      <mat-select [value]="groupMode()" (selectionChange)="groupMode.set($event.value)">
        <mat-option value="MULTIPLE" i18n="@@Cumulative">Cumulative</mat-option>
        <mat-option value="SINGLE" i18n="@@Exclusive">Exclusive</mat-option>
      </mat-select>
    </mat-form-field>

    <h3 class="sub" i18n="@@Working_hours">Working hours</h3>
    <app-business-access-form
      [value]="businessAccess()"
      [inherited]="globalBusinessAccess()"
      (valueChange)="businessAccess.set($event)"
    />

    <footer>
      <button matButton="filled" (click)="save()" [disabled]="saving() || !dirty()" i18n="@@Save">Save</button>
    </footer>
  `,
})
export class TenantGeneralComponent {
  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);
  protected readonly scope = inject(TenantScope);

  protected readonly saving = signal(false);
  private readonly settings = signal<Settings | null>(null);

  // Editable copies, re-seeded whenever the layout loads another tenant.
  protected readonly name = signal('');
  protected readonly enabled = signal(true);
  protected readonly description = signal('');
  protected readonly businessAccess = signal<BusinessAccess>({ inherited: true });
  // '' in the store means "default cumulative"; the select surfaces it as MULTIPLE.
  protected readonly groupMode = signal('MULTIPLE');

  protected readonly globalBusinessAccess = computed<BusinessAccess>(
    () => this.settings()?.businessAccess ?? { inherited: false },
  );

  protected readonly dirty = computed(() => {
    const t = this.scope.tenant();
    if (!t) return false;
    return (
      this.name().trim() !== t.name ||
      this.enabled() !== t.enabled ||
      this.description().trim() !== t.description ||
      this.groupMode() !== (t.groupMode || 'MULTIPLE') ||
      JSON.stringify(this.businessAccess()) !== JSON.stringify(t.businessAccess)
    );
  });

  constructor() {
    effect(() => {
      const t = this.scope.tenant();
      if (!t) return;
      this.name.set(t.name);
      this.enabled.set(t.enabled);
      this.description.set(t.description);
      this.groupMode.set(t.groupMode || 'MULTIPLE');
      this.businessAccess.set(t.businessAccess);
    });
    this.api.settings().subscribe({ next: (s) => this.settings.set(s) });
  }

  protected save(): void {
    const t = this.scope.tenant();
    if (!t) return;
    this.saving.set(true);
    this.api
      .updateTenant({
        ...t,
        name: this.name().trim(),
        enabled: this.enabled(),
        description: this.description().trim(),
        groupMode: this.groupMode(),
        businessAccess: this.businessAccess(),
      })
      .subscribe({
        next: (saved) => {
          this.saving.set(false);
          this.scope.tenant.set(saved);
          this.snack.open($localize`:@@Tenant_NAME_saved:Tenant "${saved.name}:NAME:" saved`, undefined, { duration: 2500 });
        },
        error: (err) => {
          this.saving.set(false);
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
