import { Component, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MAT_DIALOG_DATA, MatDialogModule } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';

interface DialogData {
  username: string;
  password: string;
}

// One-time password display (user creation / reset): the secret is shown once,
// copyable, and never retrievable again — the archway pattern.
@Component({
  selector: 'app-password-dialog',
  imports: [MatButtonModule, MatDialogModule, MatIconModule],
  styles: [
    `
      .secret {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 12px 16px;
        border: 1px solid var(--mat-sys-outline-variant);
        border-radius: 8px;
        background: var(--mat-sys-surface-container-highest);
      }
      code {
        font-family: var(--mk-mono);
        font-size: 1.05rem;
        flex: 1;
        user-select: all;
      }
      .hint {
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.85rem;
      }
    `,
  ],
  template: `
    <h2 mat-dialog-title i18n="@@Temporary_password_for_USERNAME">Temporary password for "{{ data.username }}"</h2>
    <mat-dialog-content>
      <p class="hint" i18n="@@Shown_once_copy_it_now">Shown once: copy it now, it cannot be retrieved later.</p>
      <div class="secret">
        <code>{{ data.password }}</code>
        <button matIconButton (click)="copy()" i18n-aria-label="@@Copy" aria-label="Copy">
          <mat-icon>{{ copied() ? 'check' : 'content_copy' }}</mat-icon>
        </button>
      </div>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button matButton="filled" mat-dialog-close i18n="@@Done">Done</button>
    </mat-dialog-actions>
  `,
})
export class PasswordDialogComponent {
  protected readonly data = inject<DialogData>(MAT_DIALOG_DATA);
  protected readonly copied = signal(false);

  protected copy(): void {
    void navigator.clipboard.writeText(this.data.password).then(() => this.copied.set(true));
  }
}
