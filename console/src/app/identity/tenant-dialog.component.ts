import { Component, computed, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatInputModule } from '@angular/material/input';
import { FormFieldComponent } from '../shared/form-field.component';

export interface TenantDialogResult {
  name: string;
  description: string;
}

// New tenant: its name plus the human description shown in the rail drawer.
// Resolves to the values on confirm, undefined on cancel.
@Component({
  selector: 'app-tenant-dialog',
  imports: [MatButtonModule, MatDialogModule, MatInputModule, FormFieldComponent],
  styles: [
    `
      app-form-field {
        display: block;
        width: 100%;
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

  protected readonly canConfirm = computed(() => this.name().trim().length > 0);

  protected confirm(): void {
    if (!this.canConfirm()) return;
    this.ref.close({ name: this.name().trim(), description: this.description().trim() });
  }
}
