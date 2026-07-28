import { Component, inject, LOCALE_ID, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import {
  MAT_DIALOG_DATA,
  MatDialog,
  MatDialogModule,
  MatDialogRef,
} from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatSnackBar } from '@angular/material/snack-bar';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import { DateTime } from 'luxon';
import { firstValueFrom } from 'rxjs';
import { AdminToken, ApiService } from '../api.service';
import { DialogsService } from '../shared/dialogs.service';

// Control-plane access tokens (root only, Gateway perimeter): headless access
// to the admin port. These are the FOUNDATION for a future CLI and MCP server
// driving Meerkat (PLANNED — the tooling that consumes them comes later). A
// token is minted here, shown once, and authenticates on the admin port via
// `Authorization: Bearer mk_…` with the same powers as its owner (root).
@Component({
  selector: 'app-access-tokens-page',
  imports: [MatButtonModule, MatIconModule, MatSlideToggleModule, LoadingIndicatorComponent],
  styleUrl: './access-tokens-page.component.scss',
  templateUrl: './access-tokens-page.component.html',
})
export class AccessTokensPageComponent {
  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);
  private readonly dialog = inject(MatDialog);
  private readonly dialogs = inject(DialogsService);
  private readonly locale = inject(LOCALE_ID);

  protected readonly loading = signal(true);
  protected readonly tokens = signal<AdminToken[]>([]);

  constructor() {
    this.load();
  }

  private load(): void {
    this.api.listAdminTokens().subscribe({
      next: (tokens) => {
        this.tokens.set(tokens);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  protected async create(): Promise<void> {
    const res = await firstValueFrom(
      this.dialog
        .open<TokenCreateDialogComponent, void, { name: string; days: number } | undefined>(
          TokenCreateDialogComponent,
          { width: '440px', restoreFocus: true },
        )
        .afterClosed(),
    );
    if (!res) return;
    this.api.createAdminToken(res.name, res.days).subscribe({
      next: (created) => {
        this.dialog.open(TokenRevealDialogComponent, { data: { token: created.token }, width: '520px' });
        this.load();
      },
      error: (err) => this.snack.open(errMsg(err), undefined, { duration: 4000 }),
    });
  }

  protected toggle(t: AdminToken, enabled: boolean): void {
    this.api.toggleAdminToken(t.id, enabled).subscribe({
      next: () => this.tokens.update((list) => list.map((x) => (x.id === t.id ? { ...x, enabled } : x))),
      error: (err) => {
        this.snack.open(errMsg(err), undefined, { duration: 4000 });
        this.load();
      },
    });
  }

  protected async revoke(t: AdminToken): Promise<void> {
    const ok = await this.dialogs.confirm({
      title: $localize`:@@Revoke_token_NAME:Revoke token "${t.name}:NAME:"?`,
      confirmLabel: $localize`:@@Revoke:Revoke`,
      danger: true,
    });
    if (!ok) return;
    this.api.revokeAdminToken(t.id).subscribe({
      next: () => this.tokens.update((list) => list.filter((x) => x.id !== t.id)),
      error: (err) => this.snack.open(errMsg(err), undefined, { duration: 4000 }),
    });
  }

  protected day(ts: number): string {
    return DateTime.fromSeconds(ts).reconfigure({ locale: this.locale }).toLocaleString(DateTime.DATE_MED);
  }

  protected expiryLabel(ts: number): string {
    if (!ts) return $localize`:@@never_expires:never expires`;
    return $localize`:@@expires_DATE:expires ${this.day(ts)}:DATE:`;
  }

  protected lastUsedLabel(ts: number): string {
    if (!ts) return $localize`:@@never_used:never used`;
    const rel = DateTime.fromSeconds(ts).reconfigure({ locale: this.locale }).toRelative() ?? '';
    return $localize`:@@last_used_REL:last used ${rel}:REL:`;
  }
}

// Create dialog: a name and an expiry choice. Returns {name, days} or undefined.
@Component({
  selector: 'app-token-create-dialog',
  imports: [MatButtonModule, MatDialogModule, MatFormFieldModule, MatInputModule, MatSelectModule],
  styles: [
    `
      mat-form-field {
        width: 100%;
      }
    `,
  ],
  template: `
    <h2 mat-dialog-title i18n="@@New_token">New token</h2>
    <mat-dialog-content>
      <mat-form-field>
        <mat-label i18n="@@Token_name">Token name</mat-label>
        <input
          matInput
          [value]="name()"
          (input)="name.set($any($event.target).value)"
          (keydown.enter)="confirm()"
          cdkFocusInitial
        />
      </mat-form-field>
      <mat-form-field>
        <mat-label i18n="@@Expiry">Expiry</mat-label>
        <mat-select [value]="days()" (selectionChange)="days.set($event.value)">
          <mat-option [value]="0" i18n="@@never_expires">never expires</mat-option>
          <mat-option [value]="30" i18n="@@in_30_days">30 days</mat-option>
          <mat-option [value]="90" i18n="@@in_90_days">90 days</mat-option>
          <mat-option [value]="365" i18n="@@in_1_year">1 year</mat-option>
        </mat-select>
      </mat-form-field>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button matButton mat-dialog-close i18n="@@Cancel">Cancel</button>
      <button matButton="filled" [disabled]="!name().trim()" (click)="confirm()" i18n="@@Create">Create</button>
    </mat-dialog-actions>
  `,
})
export class TokenCreateDialogComponent {
  private readonly ref = inject(MatDialogRef<TokenCreateDialogComponent>);
  protected readonly name = signal('');
  protected readonly days = signal(0);

  protected confirm(): void {
    const name = this.name().trim();
    if (name) this.ref.close({ name, days: this.days() });
  }
}

// Reveal dialog: the clear token, shown once, with a copy button.
@Component({
  selector: 'app-token-reveal-dialog',
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
        font-size: 0.95rem;
        flex: 1;
        word-break: break-all;
        user-select: all;
      }
      .hint {
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.85rem;
      }
    `,
  ],
  template: `
    <h2 mat-dialog-title i18n="@@Token_created">Token created</h2>
    <mat-dialog-content>
      <p class="hint" i18n="@@Shown_once_copy_it_now">Shown once: copy it now, it cannot be retrieved later.</p>
      <div class="secret">
        <code>{{ data.token }}</code>
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
export class TokenRevealDialogComponent {
  protected readonly data = inject<{ token: string }>(MAT_DIALOG_DATA);
  protected readonly copied = signal(false);

  protected copy(): void {
    void navigator.clipboard.writeText(this.data.token).then(() => this.copied.set(true));
  }
}

function errMsg(err: unknown): string {
  const e = err as { error?: { error?: string } };
  return typeof e?.error?.error === 'string' ? e.error.error : $localize`:@@Request_failed:Request failed`;
}
