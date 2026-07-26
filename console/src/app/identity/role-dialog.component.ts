import { COMMA, ENTER } from '@angular/cdk/keycodes';
import { Component, computed, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatChipInputEvent, MatChipsModule } from '@angular/material/chips';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { FormFieldComponent } from '../shared/form-field.component';

export interface RoleDialogData {
  title: string;
  confirmLabel: string;
  name?: string;
  description?: string;
  tags?: string[];
}

export interface RoleDialogResult {
  name: string;
  description: string;
  tags: string[];
}

// Create/edit a catalogue role: its technical name, the human description that
// the tenant screens put forward, and the tags the groups matrix filters on.
// Resolves to the values on confirm, undefined on cancel.
@Component({
  selector: 'app-role-dialog',
  imports: [
    MatButtonModule,
    MatChipsModule,
    MatDialogModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    FormFieldComponent,
  ],
  styles: [
    `
      app-form-field,
      mat-form-field {
        display: block;
        width: 100%;
      }
    `,
  ],
  template: `
    <h2 mat-dialog-title>{{ data.title }}</h2>
    <mat-dialog-content>
      <app-form-field i18n-label="@@Role_name" label="Role name">
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
          rows="3"
          [value]="description()"
          (input)="description.set($any($event.target).value)"
        ></textarea>
      </app-form-field>
      <mat-form-field>
        <mat-label i18n="@@Tags">Tags</mat-label>
        <!-- the input lives INSIDE the grid so it flows on the chips' line -->
        <mat-chip-grid #chipGrid>
          @for (t of tags(); track t) {
            <mat-chip-row (removed)="removeTag(t)">
              {{ t }}
              <button matChipRemove [attr.aria-label]="t" type="button">
                <mat-icon>cancel</mat-icon>
              </button>
            </mat-chip-row>
          }
          <input
            [matChipInputFor]="chipGrid"
            [matChipInputSeparatorKeyCodes]="separators"
            (matChipInputTokenEnd)="addTag($event)"
          />
        </mat-chip-grid>
      </mat-form-field>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button matButton mat-dialog-close i18n="@@Cancel">Cancel</button>
      <button matButton="filled" [disabled]="!canConfirm()" (click)="confirm()">
        {{ data.confirmLabel }}
      </button>
    </mat-dialog-actions>
  `,
})
export class RoleDialogComponent {
  protected readonly data = inject<RoleDialogData>(MAT_DIALOG_DATA);
  private readonly ref = inject(MatDialogRef<RoleDialogComponent, RoleDialogResult>);
  protected readonly name = signal(this.data.name ?? '');
  protected readonly description = signal(this.data.description ?? '');
  protected readonly tags = signal<string[]>([...(this.data.tags ?? [])]);
  protected readonly separators = [ENTER, COMMA];

  protected readonly canConfirm = computed(() => this.name().trim().length > 0);

  protected addTag(event: MatChipInputEvent): void {
    const tag = event.value.trim();
    if (tag && !this.tags().includes(tag)) this.tags.update((t) => [...t, tag]);
    event.chipInput.clear();
  }

  protected removeTag(tag: string): void {
    this.tags.update((t) => t.filter((x) => x !== tag));
  }

  protected confirm(): void {
    if (!this.canConfirm()) return;
    this.ref.close({
      name: this.name().trim(),
      description: this.description().trim(),
      tags: this.tags(),
    });
  }
}
