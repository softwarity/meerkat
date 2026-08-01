import { Component, inject, input, output } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatDialog } from '@angular/material/dialog';
import { MatDividerModule } from '@angular/material/divider';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { ApiService, User } from '../../api.service';
import { DialogsService } from '../../shared/dialogs.service';
import { ExternalIdentitiesComponent } from '../external-identities.component';
import { LoginHistoryComponent } from '../login-history.component';
import { MfaSelectComponent } from '../mfa-select.component';
import { PasswordDialogComponent } from '../password-dialog.component';

// A user's options, hosted in the users-page right drawer (opened by clicking a
// row). Capabilities, the second-factor policy and account actions all live
// here — nothing is edited inline on the table anymore.
@Component({
  selector: 'app-user-editor',
  imports: [
    MatButtonModule,
    MatDividerModule,
    MatIconModule,
    MatTooltipModule,
    ExternalIdentitiesComponent,
    LoginHistoryComponent,
    MfaSelectComponent,
  ],
  templateUrl: './user-editor.component.html',
  styleUrl: './user-editor.component.scss',
})
export class UserEditorComponent {
  readonly user = input.required<User>();
  // Resolved global second-factor policy — what a user's "Inherited" means.
  readonly globalMfaLabel = input.required<string>();
  readonly meId = input.required<string>();

  // saved: a field changed, here is the fresh user (the page updates its list
  // and keeps the drawer in sync). closed: drawer dismissed or user deleted.
  readonly saved = output<User>();
  readonly closed = output<void>();

  private readonly api = inject(ApiService);
  private readonly dialog = inject(MatDialog);
  private readonly dialogs = inject(DialogsService);

  protected readonly isMe = () => this.user().id === this.meId();

  protected setMfa(mfaRequired: string): void {
    this.apply({ ...this.user(), mfaRequired });
  }

  private apply(next: User): void {
    this.api.updateUser(next).subscribe({
      next: (fresh) => this.saved.emit(fresh),
      // On error, re-emit the authoritative user so the toggle snaps back.
      error: () => this.saved.emit(this.user()),
    });
  }

  protected resetPassword(): void {
    this.api.resetPassword(this.user().id).subscribe({
      next: ({ password }) =>
        this.dialog.open(PasswordDialogComponent, {
          data: { username: this.user().username, password },
        }),
    });
  }

  protected async remove(): Promise<void> {
    const u = this.user();
    const ok = await this.dialogs.confirm({
      title: $localize`:@@Delete_user_USERNAME:Delete user "${u.username}:USERNAME:"?`,
      confirmLabel: $localize`:@@Delete:Delete`,
      danger: true,
    });
    if (!ok) return;
    this.api.deleteUser(u.id).subscribe({ next: () => this.closed.emit() });
  }
}
