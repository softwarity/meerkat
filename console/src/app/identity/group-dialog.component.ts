import { Component, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';

export interface GroupDialogData {
  title: string;
  confirmLabel: string;
  name?: string;
  description?: string;
}

export interface GroupDialogResult {
  name: string;
  description: string;
}

// A group's name + description, used to create and to edit (RBAC-02).
@Component({
  selector: 'app-group-dialog',
  imports: [MatButtonModule, MatDialogModule, MatFormFieldModule, MatInputModule],
  styles: [
    `
      mat-form-field {
        width: 100%;
      }
    `,
  ],
  template: `
    <h2 mat-dialog-title>{{ data.title }}</h2>
    <mat-dialog-content>
      <mat-form-field>
        <mat-label i18n="@@Group_name">Group name</mat-label>
        <input
          matInput
          [value]="name()"
          (input)="name.set($any($event.target).value)"
          (keydown.enter)="confirm()"
          cdkFocusInitial
        />
      </mat-form-field>
      <mat-form-field>
        <mat-label i18n="@@Description">Description</mat-label>
        <textarea matInput rows="2" [value]="description()" (input)="description.set($any($event.target).value)"></textarea>
      </mat-form-field>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button matButton mat-dialog-close i18n="@@Cancel">Cancel</button>
      <button matButton="filled" [disabled]="!name().trim()" (click)="confirm()">
        {{ data.confirmLabel }}
      </button>
    </mat-dialog-actions>
  `,
})
export class GroupDialogComponent {
  protected readonly data = inject<GroupDialogData>(MAT_DIALOG_DATA);
  private readonly ref = inject(MatDialogRef<GroupDialogComponent, GroupDialogResult>);
  protected readonly name = signal(this.data.name ?? '');
  protected readonly description = signal(this.data.description ?? '');

  protected confirm(): void {
    const name = this.name().trim();
    if (name) this.ref.close({ name, description: this.description().trim() });
  }
}
