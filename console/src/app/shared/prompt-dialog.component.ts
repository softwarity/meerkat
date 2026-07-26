import { Component, computed, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';

export interface PromptData {
  title: string;
  label: string;
  confirmLabel: string;
  initial?: string;
  // Type-to-confirm: the confirm button stays disabled until the input matches
  // this exact string (destructive actions — e.g. type the tenant name).
  requireMatch?: string;
  danger?: boolean;
}

// A themed single-field prompt — replaces the native prompt(). Resolves to the
// trimmed value on confirm, undefined on cancel. Callers pass localized strings.
@Component({
  selector: 'app-prompt-dialog',
  imports: [MatButtonModule, MatDialogModule, MatFormFieldModule, MatInputModule],
  styles: [
    `
      mat-form-field {
        width: 100%;
      }
      .danger {
        --mdc-filled-button-container-color: var(--mat-sys-error);
        --mdc-filled-button-label-text-color: var(--mat-sys-on-error);
      }
    `,
  ],
  template: `
    <h2 mat-dialog-title>{{ data.title }}</h2>
    <mat-dialog-content>
      <mat-form-field>
        <mat-label>{{ data.label }}</mat-label>
        <input
          matInput
          [value]="value()"
          (input)="value.set($any($event.target).value)"
          (keydown.enter)="confirm()"
          cdkFocusInitial
        />
      </mat-form-field>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button matButton mat-dialog-close i18n="@@Cancel">Cancel</button>
      <button matButton="filled" [class.danger]="data.danger" [disabled]="!canConfirm()" (click)="confirm()">
        {{ data.confirmLabel }}
      </button>
    </mat-dialog-actions>
  `,
})
export class PromptDialogComponent {
  protected readonly data = inject<PromptData>(MAT_DIALOG_DATA);
  private readonly ref = inject(MatDialogRef<PromptDialogComponent, string>);
  protected readonly value = signal(this.data.initial ?? '');

  protected readonly canConfirm = computed(() => {
    const v = this.value().trim();
    return this.data.requireMatch != null ? v === this.data.requireMatch : v.length > 0;
  });

  protected confirm(): void {
    if (this.canConfirm()) this.ref.close(this.value().trim());
  }
}
