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
  styles: [
    `
      .banner {
        display: flex;
        align-items: center;
        gap: 16px;
        padding: 12px 24px;
      }
      .banner h1 {
        font-size: 1.15rem;
        font-weight: 500;
        margin: 0;
        flex: 1;
      }
      .content {
        padding: 0 24px 24px;
        display: grid;
        gap: 16px;
        max-width: 820px;
      }
      .planned {
        display: flex;
        align-items: flex-start;
        gap: 10px;
        padding: 12px 16px;
        border: 1px dashed color-mix(in srgb, var(--mat-sys-primary) 45%, transparent);
        border-radius: 10px;
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.85rem;
      }
      .planned mat-icon {
        color: var(--mat-sys-primary);
        /* Keep the icon at full size in the flex row: without this the long
           text shrinks the box and the glyph gets clipped. */
        flex-shrink: 0;
        overflow: visible;
      }
      .token {
        display: grid;
        grid-template-columns: 1fr auto auto;
        align-items: center;
        gap: 4px 16px;
        padding: 12px 16px 12px 18px;
        border: 1px solid var(--mat-sys-outline-variant);
        border-radius: 10px;
        position: relative;
        overflow: hidden;
      }
      .token::before {
        content: '';
        position: absolute;
        inset: 0 auto 0 0;
        width: 3px;
        background: var(--mat-sys-primary);
        opacity: 0.7;
      }
      .token .name {
        font-weight: 500;
      }
      .token .prefix {
        font-family: var(--mk-mono);
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.85rem;
      }
      .token .meta {
        grid-column: 1 / -1;
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.8rem;
      }
      .token.off {
        opacity: 0.55;
      }
      .empty {
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.9rem;
        padding: 8px 0;
      }
    `,
  ],
  template: `
    <div class="banner">
      <h1 i18n="@@Access_tokens">Access tokens</h1>
      <button matButton="filled" (click)="create()">
        <mat-icon>add</mat-icon>
        <ng-container i18n="@@New_token">New token</ng-container>
      </button>
    </div>

    <div class="content">
      <div class="planned">
        <mat-icon>smart_toy</mat-icon>
        <span i18n="@@Access_tokens_planned">
          Control-plane tokens grant browserless access to the admin port with your powers. They are
          the foundation for a Meerkat CLI and MCP server, which let an AI or a script manage the
          gateway. That tooling is planned; the tokens work today for your own automation.
        </span>
      </div>

      @if (loading()) {
        <loading-indicator withContainer />
      } @else {
        @for (t of tokens(); track t.id) {
          <div class="token" [class.off]="!t.enabled">
            <span class="name">{{ t.name }}</span>
            <mat-slide-toggle [checked]="t.enabled" (change)="toggle(t, $event.checked)" />
            <button matIconButton (click)="revoke(t)" i18n-matTooltip="@@Revoke" matTooltip="Revoke">
              <mat-icon>delete</mat-icon>
            </button>
            <span class="meta">
              <code class="prefix">{{ t.prefix }}…</code>
              &nbsp;·&nbsp;<ng-container i18n="@@Created_on">Created on</ng-container> {{ day(t.createdAt) }}
              &nbsp;·&nbsp;{{ expiryLabel(t.expiresAt) }}
              &nbsp;·&nbsp;{{ lastUsedLabel(t.lastUsedAt) }}
            </span>
          </div>
        } @empty {
          <p class="empty" i18n="@@No_access_tokens">No access token yet.</p>
        }
      }
    </div>
  `,
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
    if (!ts) return $localize`:@@Never_expires:never expires`;
    return $localize`:@@Expires_DATE:expires ${this.day(ts)}:DATE:`;
  }

  protected lastUsedLabel(ts: number): string {
    if (!ts) return $localize`:@@Never_used:never used`;
    const rel = DateTime.fromSeconds(ts).reconfigure({ locale: this.locale }).toRelative() ?? '';
    return $localize`:@@Last_used_REL:last used ${rel}:REL:`;
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
          <mat-option [value]="0" i18n="@@Never_expires">never expires</mat-option>
          <mat-option [value]="30" i18n="@@In_30_days">30 days</mat-option>
          <mat-option [value]="90" i18n="@@In_90_days">90 days</mat-option>
          <mat-option [value]="365" i18n="@@In_1_year">1 year</mat-option>
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
