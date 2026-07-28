import { Component, computed, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatSnackBar } from '@angular/material/snack-bar';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import { ApiService, MailRelay } from '../api.service';
import { MeService } from '../me.service';
import { FormFieldComponent } from '../shared/form-field.component';

// Enough to catch a typo, not to rule on RFC 5322: the relay itself is the real
// judge, and the point here is only to stop a pointless round-trip.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// The mail relay (AUTH-20) — INFRA plane. A third-party service reached by host
// and port, with credentials: the same nature as a route's upstream, and the
// reason it does not sit with the application settings. What the recipient
// sees, the sender address, belongs to the application (Security page).
@Component({
  selector: 'app-mail-relay-page',
  imports: [
    MatButtonModule,
    MatCardModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatSelectModule,
    LoadingIndicatorComponent,
    FormFieldComponent,
  ],
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
        max-width: 720px;
      }
      mat-card {
        padding: 16px 20px;
      }
      .hint {
        margin: 0 0 12px;
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.85rem;
      }
      .grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 0 16px;
      }
      /* Field and button on one optical line. The field is subscriptSizing
         dynamic (see the template): with the reserved hint line below the
         input, centring the row drops the button visibly lower than the field. */
      .test {
        display: flex;
        align-items: center;
        gap: 12px;
      }
      .field {
        width: 280px;
      }
      /* One line, never resizable: it reads as an input but a browser never
         offers credential autofill on a textarea, so the relay password stops
         attracting "save this password?" for the console's own account. */
      .oneline {
        resize: none;
        overflow: hidden;
        white-space: nowrap;
      }
      .actions {
        display: flex;
        justify-content: flex-end;
      }
    `,
  ],
  template: `
    @if (loading()) {
      <loading-indicator withContainer />
    } @else {
      <div class="banner">
        <h1 i18n="@@Mail_relay">Mail relay</h1>
      </div>

      <div class="content">
        <mat-card appearance="outlined">
          <p class="hint" i18n="@@Mail_relay_hint">
            The SMTP server that delivers account e-mails: confirmations, password resets,
            administrator notifications. The sender address is set in the application settings.
          </p>
          <div class="grid">
            <mat-form-field>
              <mat-label i18n="@@SMTP_host">Host</mat-label>
              <input matInput [value]="host()" (input)="host.set($any($event.target).value)" placeholder="smtp.example.com" />
            </mat-form-field>
            <mat-form-field>
              <mat-label i18n="@@SMTP_port">Port</mat-label>
              <input matInput type="number" [value]="port()" (input)="port.set(+$any($event.target).value)" placeholder="587" />
            </mat-form-field>
            <mat-form-field>
              <mat-label i18n="@@SMTP_security">Security</mat-label>
              <mat-select [value]="security()" (selectionChange)="security.set($event.value)">
                <mat-option value="starttls">STARTTLS</mat-option>
                <mat-option value="tls">TLS</mat-option>
                <mat-option value="none" i18n="@@None">None</mat-option>
              </mat-select>
            </mat-form-field>
            <mat-form-field>
              <mat-label i18n="@@SMTP_username">Username</mat-label>
              <input matInput [value]="username()" (input)="username.set($any($event.target).value)" autocomplete="off" />
            </mat-form-field>
            <app-form-field
              i18n-label="@@SMTP_password"
              label="Password"
              revealable
              masked
              allowVault="secret"
              vaultScope="infra"
              [clearable]="false"
            >
              <textarea
                matInput
                rows="1"
                class="oneline"
                spellcheck="false"
                autocapitalize="off"
                autocorrect="off"
                [value]="password()"
                (input)="password.set($any($event.target).value)"
                (keydown.enter)="$event.preventDefault()"
                [placeholder]="passwordSet() ? '••••••••' : ''"
              ></textarea>
            </app-form-field>
          </div>

          <div class="test">
            <mat-form-field class="field" subscriptSizing="dynamic">
              <mat-label i18n="@@Test_recipient">Test recipient</mat-label>
              <input
                matInput
                type="email"
                [value]="testTo()"
                (input)="testTo.set($any($event.target).value)"
                placeholder="you@example.com"
              />
            </mat-form-field>
            <button matButton (click)="test()" [disabled]="testing() || !host().trim() || !recipientOK()">
              <!-- The one place with a slow round-trip and no other feedback: the
                   icon spins while the relay is being tried. Written without any
                   whitespace inside the branches — with preserveWhitespaces on,
                   an indented @if is several root nodes and the icon never
                   reaches matButton's icon slot (NG8011). -->
              @if (testing()) {<mat-icon spin>autorenew</mat-icon>} @else {<mat-icon>send</mat-icon>}
              <ng-container i18n="@@Send_a_test">Send a test</ng-container>
            </button>
          </div>
        </mat-card>

        <div class="actions">
          <button matButton="filled" (click)="save()" [disabled]="saving()" i18n="@@Save">Save</button>
        </div>
      </div>
    }
  `,
})
export class MailRelayPageComponent {
  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);
  private readonly me = inject(MeService);

  protected readonly loading = signal(true);
  protected readonly saving = signal(false);
  protected readonly testing = signal(false);

  protected readonly host = signal('');
  protected readonly port = signal(587);
  protected readonly security = signal('starttls');
  protected readonly username = signal('');
  protected readonly password = signal('');
  protected readonly passwordSet = signal(false);
  protected readonly testTo = signal('');

  // Nothing to send to, nothing to test: the button stays off until the address
  // is at least shaped like one.
  protected readonly recipientOK = computed(() => EMAIL_RE.test(this.testTo().trim()));

  constructor() {
    // One's own address is the obvious recipient: prefill it, so testing a relay
    // is one click.
    this.testTo.set(this.me.user()?.email ?? '');
    this.api.mailRelay().subscribe({
      next: (r) => {
        this.apply(r);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  private apply(r: MailRelay): void {
    this.host.set(r.host ?? '');
    this.port.set(r.port || 587);
    this.security.set(r.security || 'starttls');
    this.username.set(r.username ?? '');
    this.passwordSet.set(!!r.passwordSet);
    this.password.set('');
  }

  // The relay as the form has it right now — what both Save and Test act on.
  private current(): MailRelay {
    return {
      host: this.host().trim(),
      port: this.port() || 587,
      security: this.security(),
      username: this.username().trim(),
      password: this.password(), // '' keeps the stored one
    };
  }

  protected save(): void {
    this.saving.set(true);
    this.api.saveMailRelay(this.current()).subscribe({
      next: (saved) => {
        this.apply(saved);
        this.saving.set(false);
        this.snack.open($localize`:@@Settings_saved:Settings saved`, undefined, { duration: 2500 });
      },
      error: (err: unknown) => {
        this.saving.set(false);
        this.fail(err);
      },
    });
  }

  // Tries what is ON SCREEN, saving nothing: an admin checks a relay works
  // before committing to it.
  protected test(): void {
    this.testing.set(true);
    this.api.testMailRelay(this.current(), this.testTo().trim()).subscribe({
      next: ({ sent }) => {
        this.testing.set(false);
        this.snack.open($localize`:@@Test_email_sent_to_ADDR:Test email sent to ${sent}:ADDR:`, undefined, {
          duration: 4000,
        });
      },
      error: (err: unknown) => {
        this.testing.set(false);
        this.fail(err);
      },
    });
  }

  private fail(err: unknown): void {
    const e = err as { error?: { error?: string } };
    this.snack.open(
      typeof e?.error?.error === 'string' ? e.error.error : $localize`:@@Request_failed:Request failed`,
      undefined,
      { duration: 6000 },
    );
  }
}
