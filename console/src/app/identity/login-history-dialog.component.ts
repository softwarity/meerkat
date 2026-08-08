import { Component, inject } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MAT_DIALOG_DATA, MatDialogModule } from '@angular/material/dialog';
import { LoginHistoryComponent } from './login-history.component';

export interface LoginHistoryDialogData {
  tenantId: string;
  userId: string;
  username: string;
}

// The members matrix has no per-member drawer: a member's sign-in history
// opens in this dialog instead (tenant-scoped endpoint).
@Component({
  selector: 'app-login-history-dialog',
  imports: [MatButtonModule, MatDialogModule, LoginHistoryComponent],
  template: `
    <h2 mat-dialog-title>
      <ng-container i18n="@@Sign_in_history">Sign-in history</ng-container>
      - {{ data.username }}
    </h2>
    <mat-dialog-content>
      <app-login-history [userId]="data.userId" [tenantId]="data.tenantId" />
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button matButton mat-dialog-close i18n="@@Close">Close</button>
    </mat-dialog-actions>
  `,
})
export class LoginHistoryDialogComponent {
  protected readonly data = inject<LoginHistoryDialogData>(MAT_DIALOG_DATA);
}
