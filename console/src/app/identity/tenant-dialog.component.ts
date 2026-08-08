import { Component, computed, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { FormFieldComponent } from '../shared/form-field.component';

export interface TenantDialogResult {
  name: string;
  description: string;
  groupMode: string;
}

// New tenant: its name, the human description shown in the rail drawer, and the
// group mode (RBAC-03). The mode is offered here on purpose - it is a founding
// choice for how the tenant's groups combine, and burying it in the edit page
// would leave the feature undiscovered. Resolves to the values on confirm,
// undefined on cancel.
@Component({
  selector: 'app-tenant-dialog',
  imports: [
    MatButtonModule,
    MatDialogModule,
    MatFormFieldModule,
    MatInputModule,
    MatSelectModule,
    FormFieldComponent,
  ],
  styles: [
    `
      app-form-field,
      .mode {
        display: block;
        width: 100%;
      }
      .mode-hint {
        margin: 4px 0 0;
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.8rem;
      }
    `,
  ],
  template: `
    <h2 mat-dialog-title i18n="@@New_tenant">New tenant</h2>
    <mat-dialog-content>
      <app-form-field i18n-label="@@Tenant_name" label="Tenant name">
        <input
          matInput
          [value]="name()"
          (input)="name.set($any($event.target).value)"
          (keydown.enter)="confirm()"
          cdkFocusInitial
        />
      </app-form-field>
      <app-form-field i18n-label="@@Description" label="Description">
        <textarea
          matInput
          rows="2"
          [value]="description()"
          (input)="description.set($any($event.target).value)"
        ></textarea>
      </app-form-field>
      <mat-form-field class="mode">
        <mat-label i18n="@@Group_mode">Group mode</mat-label>
        <mat-select [value]="groupMode()" (selectionChange)="groupMode.set($event.value)">
          <mat-option value="MULTIPLE" i18n="@@Cumulative">Cumulative</mat-option>
          <mat-option value="SINGLE" i18n="@@Exclusive">Exclusive</mat-option>
        </mat-select>
      </mat-form-field>
      <p class="mode-hint" i18n="@@Tenant_group_mode_hint">
        Cumulative merges the roles of every assigned group; exclusive makes members pick ONE group
        when they enter this tenant.
      </p>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button matButton mat-dialog-close i18n="@@Cancel">Cancel</button>
      <button matButton="filled" [disabled]="!canConfirm()" (click)="confirm()" i18n="@@Create">
        Create
      </button>
    </mat-dialog-actions>
  `,
})
export class TenantDialogComponent {
  private readonly ref = inject(MatDialogRef<TenantDialogComponent, TenantDialogResult>);
  protected readonly name = signal('');
  protected readonly description = signal('');
  protected readonly groupMode = signal('MULTIPLE');

  protected readonly canConfirm = computed(() => this.name().trim().length > 0);

  protected confirm(): void {
    if (!this.canConfirm()) return;
    this.ref.close({
      name: this.name().trim(),
      description: this.description().trim(),
      groupMode: this.groupMode(),
    });
  }
}
