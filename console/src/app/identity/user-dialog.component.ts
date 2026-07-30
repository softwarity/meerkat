import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject, signal } from '@angular/core';
import { FormField, form, required } from '@angular/forms/signals';
import { MatButtonModule } from '@angular/material/button';
import { MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { ApiService, User } from '../api.service';

// User creation — identity only; the generated one-time password comes back in
// the dialog result, superpowers are toggled afterwards on the users table.
@Component({
  selector: 'app-user-dialog',
  imports: [FormField, MatButtonModule, MatDialogModule, MatFormFieldModule, MatInputModule],
  styles: [
    `
      mat-form-field {
        width: 100%;
      }
      /* One line, never resizable: identity fields on a textarea look like
         inputs but are invisible to the browser's autofill, which otherwise
         offers the SIGNED-IN admin's own name and address when creating
         someone else's account. */
      .error {
        color: var(--mat-sys-error);
        background: color-mix(in srgb, var(--mat-sys-error) 12%, transparent);
        border-radius: 6px;
        padding: 10px 14px;
        white-space: pre-wrap;
      }
    `,
  ],
  template: `
    <h2 mat-dialog-title i18n="@@New_user">New user</h2>
    <mat-dialog-content>
      <mat-form-field>
        <mat-label i18n="@@Username">Username</mat-label>
        <textarea
          matInput
          rows="1"
          class="oneline"
          spellcheck="false"
          autocapitalize="off"
          autocorrect="off"
          [formField]="f.username"
          (keydown.enter)="$event.preventDefault()"
        ></textarea>
      </mat-form-field>
      <mat-form-field>
        <mat-label i18n="@@Full_name">Full name</mat-label>
        <textarea
          matInput
          rows="1"
          class="oneline"
          spellcheck="false"
          autocapitalize="off"
          autocorrect="off"
          [formField]="f.fullname"
          (keydown.enter)="$event.preventDefault()"
        ></textarea>
      </mat-form-field>
      <mat-form-field>
        <mat-label i18n="@@Email">Email</mat-label>
        <textarea
          matInput
          rows="1"
          class="oneline"
          spellcheck="false"
          autocapitalize="off"
          autocorrect="off"
          [formField]="f.email"
          (keydown.enter)="$event.preventDefault()"
        ></textarea>
      </mat-form-field>
      @if (error()) {
        <div class="error">{{ error() }}</div>
      }
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button matButton mat-dialog-close i18n="@@Cancel">Cancel</button>
      <button matButton="filled" (click)="save()" [disabled]="saving() || !f().valid()" i18n="@@Create">
        Create
      </button>
    </mat-dialog-actions>
  `,
})
export class UserDialogComponent {
  private readonly api = inject(ApiService);
  private readonly ref = inject(MatDialogRef<UserDialogComponent>);

  protected readonly model = signal({ username: '', fullname: '', email: '' });
  protected readonly f = form(this.model, (p) => {
    required(p.username);
  });

  protected readonly error = signal('');
  protected readonly saving = signal(false);

  protected save(): void {
    this.error.set('');
    this.saving.set(true);
    const m = this.model();
    this.api
      .createUser({
        username: m.username.trim(),
        fullname: m.fullname.trim(),
        email: m.email.trim(),
        enabled: true,
      })
      .subscribe({
        next: (result: { user: User; password: string }) => this.ref.close(result),
        error: (err: unknown) => {
          this.saving.set(false);
          this.error.set(
            err instanceof HttpErrorResponse && typeof err.error?.error === 'string'
              ? err.error.error
              : $localize`:@@Save_failed:Save failed`,
          );
        },
      });
  }
}
