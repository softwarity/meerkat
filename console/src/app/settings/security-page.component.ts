import { Component, inject, LOCALE_ID, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatSnackBar } from '@angular/material/snack-bar';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import { ApiService, Settings } from '../api.service';
import { humanDuration } from '../shared/duration';

const TRUST_TTL_CHOICES = ['P1D', 'P7D', 'P14D', 'P30D'];

// Gateway-wide security policy (root only): second factor (MFA-04), passkeys
// (AUTH-15), API tokens (AUTH-16), self-registration (AUTH-20), rate limiting
// (SEC-10), trusted browsers (MFA-03), and the outbound e-mail (SMTP) the
// account flows rely on. A full PUT of /api/settings — the other fields ride
// along untouched.
@Component({
  selector: 'app-security-page',
  imports: [
    MatButtonModule,
    MatCardModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatSelectModule,
    MatSlideToggleModule,
    LoadingIndicatorComponent,
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
      h3 {
        margin: 0 0 6px;
        font-size: 0.95rem;
        font-weight: 500;
      }
      .hint {
        margin: 0 0 12px;
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.85rem;
      }
      .ttl {
        width: 220px;
        margin-top: 12px;
      }
      .field {
        width: 280px;
      }
      .actions {
        display: flex;
        justify-content: flex-end;
      }
      .rl-row {
        display: flex;
        gap: 16px;
        flex-wrap: wrap;
        margin-top: 12px;
      }
      .rl-num {
        width: 170px;
      }
      .smtp-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 0 16px;
      }
      .smtp-test {
        display: flex;
        align-items: center;
        gap: 12px;
      }
    `,
  ],
  template: `
    @if (loading()) {
      <loading-indicator withContainer />
    } @else {
      <div class="banner">
        <h1 i18n="@@Security">Security</h1>
      </div>

      <div class="content">
        <mat-card appearance="outlined">
          <h3 i18n="@@Two_factor">Two-factor</h3>
          <p class="hint" i18n="@@MFA_global_hint">
            Require a second factor for every user. Organizations and members can override this.
          </p>
          <mat-slide-toggle [checked]="mfaRequired()" (change)="mfaRequired.set($event.checked)">
            <ng-container i18n="@@Require_two_factor">Require two-factor for everyone</ng-container>
          </mat-slide-toggle>
        </mat-card>

        <mat-card appearance="outlined">
          <h3 i18n="@@Email_SMTP">Email (SMTP)</h3>
          <p class="hint" i18n="@@SMTP_hint">
            Outbound email: account confirmations and administrator notifications. Save, then send a test.
          </p>
          <div class="smtp-grid">
            <mat-form-field>
              <mat-label i18n="@@SMTP_host">Host</mat-label>
              <input matInput [value]="smtpHost()" (input)="smtpHost.set($any($event.target).value)" placeholder="smtp.example.com" />
            </mat-form-field>
            <mat-form-field>
              <mat-label i18n="@@SMTP_port">Port</mat-label>
              <input matInput type="number" [value]="smtpPort()" (input)="smtpPort.set(+$any($event.target).value)" placeholder="587" />
            </mat-form-field>
            <mat-form-field>
              <mat-label i18n="@@SMTP_security">Security</mat-label>
              <mat-select [value]="smtpSecurity()" (selectionChange)="smtpSecurity.set($event.value)">
                <mat-option value="starttls">STARTTLS</mat-option>
                <mat-option value="tls">TLS</mat-option>
                <mat-option value="none" i18n="@@None">None</mat-option>
              </mat-select>
            </mat-form-field>
            <mat-form-field>
              <mat-label i18n="@@SMTP_username">Username</mat-label>
              <input matInput [value]="smtpUsername()" (input)="smtpUsername.set($any($event.target).value)" autocomplete="off" />
            </mat-form-field>
            <mat-form-field>
              <mat-label i18n="@@SMTP_password">Password</mat-label>
              <input
                matInput
                type="password"
                [value]="smtpPassword()"
                (input)="smtpPassword.set($any($event.target).value)"
                autocomplete="new-password"
                [placeholder]="smtpPasswordSet() ? '••••••••' : ''"
              />
            </mat-form-field>
            <mat-form-field>
              <mat-label i18n="@@SMTP_from">From</mat-label>
              <input matInput [value]="smtpFrom()" (input)="smtpFrom.set($any($event.target).value)" placeholder="Meerkat <no-reply@example.com>" />
            </mat-form-field>
          </div>
          <div class="smtp-test">
            <mat-form-field class="field">
              <mat-label i18n="@@Test_recipient">Test recipient</mat-label>
              <input matInput type="email" [value]="smtpTestTo()" (input)="smtpTestTo.set($any($event.target).value)" i18n-placeholder="@@Your_account_email" placeholder="your account email" />
            </mat-form-field>
            <button matButton (click)="testSmtp()" [disabled]="saving() || !smtpHost().trim()">
              <mat-icon>send</mat-icon>
              <ng-container i18n="@@Save_and_send_test">Save and send a test</ng-container>
            </button>
          </div>
        </mat-card>

        <mat-card appearance="outlined">
          <h3 i18n="@@Rate_limiting">Rate limiting</h3>
          <p class="hint" i18n="@@Rate_limiting_hint">
            Throttles brute-force attempts: failed sign-ins per address and account within the
            window, and wrong two-factor codes per account. Zero disables a limiter.
          </p>
          <div class="rl-row">
            <mat-form-field class="rl-num">
              <mat-label i18n="@@Failed_sign_ins">Failed sign-ins</mat-label>
              <input matInput type="number" min="0" max="1000" [value]="rlLogin()" (input)="rlLogin.set(+$any($event.target).value)" />
            </mat-form-field>
            <mat-form-field class="rl-num">
              <mat-label i18n="@@Wrong_codes">Wrong 2FA codes</mat-label>
              <input matInput type="number" min="0" max="100" [value]="rlTotp()" (input)="rlTotp.set(+$any($event.target).value)" />
            </mat-form-field>
            <mat-form-field class="ttl">
              <mat-label i18n="@@Within">Within</mat-label>
              <mat-select [value]="rlWindow()" (selectionChange)="rlWindow.set($event.value)">
                @for (d of rlWindows; track d) {
                  <mat-option [value]="d">{{ human(d) }}</mat-option>
                }
              </mat-select>
            </mat-form-field>
          </div>
        </mat-card>

        <mat-card appearance="outlined">
          <h3 i18n="@@Self_registration">Self-registration</h3>
          <p class="hint" i18n="@@Self_registration_hint">
            Let visitors create their own account on the sign-in page. The address is confirmed by
            email, administrators are notified, and the account waits until someone grants it access.
            Requires a configured SMTP server (Application, General).
          </p>
          <mat-slide-toggle [checked]="selfRegistration()" (change)="selfRegistration.set($event.checked)">
            <ng-container i18n="@@Allow_self_registration">Allow self-registration (local accounts)</ng-container>
          </mat-slide-toggle>
          @if (selfRegistration()) {
            <br />
            <mat-slide-toggle [checked]="selfRegisterCaptcha()" (change)="selfRegisterCaptcha.set($event.checked)">
              <ng-container i18n="@@Require_captcha">Require the anti-robot check (built-in captcha)</ng-container>
            </mat-slide-toggle>
          }
        </mat-card>

        <mat-card appearance="outlined">
          <h3 i18n="@@Passkeys">Passkeys</h3>
          <p class="hint" i18n="@@Passkeys_global_hint">
            Let users register passkeys and sign in with them instead of the password and second factor.
          </p>
          <mat-slide-toggle [checked]="passkeysAllowed()" (change)="passkeysAllowed.set($event.checked)">
            <ng-container i18n="@@Allow_passkeys">Allow passkeys</ng-container>
          </mat-slide-toggle>
        </mat-card>

        <mat-card appearance="outlined">
          <h3 i18n="@@API_tokens">API tokens</h3>
          <p class="hint" i18n="@@API_tokens_hint">
            Let users mint personal access tokens (Profile, Security) to call the API routes behind
            the gateway without a browser session. A token acts with the user's context at creation.
          </p>
          <mat-slide-toggle [checked]="apiTokens()" (change)="apiTokens.set($event.checked)">
            <ng-container i18n="@@Allow_API_tokens">Allow personal API tokens</ng-container>
          </mat-slide-toggle>
        </mat-card>

        <mat-card appearance="outlined">
          <h3 i18n="@@Trusted_browsers">Trusted browsers</h3>
          <p class="hint" i18n="@@Trusted_browsers_hint">
            Let users skip the two-factor challenge on a browser they mark as trusted, until it expires.
          </p>
          <mat-slide-toggle [checked]="trustAllowed()" (change)="trustAllowed.set($event.checked)">
            <ng-container i18n="@@Allow_trusted_browsers">Allow trusted browsers</ng-container>
          </mat-slide-toggle>
          @if (trustAllowed()) {
            <mat-form-field class="ttl">
              <mat-label i18n="@@Trust_duration">Trust duration</mat-label>
              <mat-select [value]="trustTtl()" (selectionChange)="trustTtl.set($event.value)">
                @for (d of ttlChoices; track d) {
                  <mat-option [value]="d">{{ human(d) }}</mat-option>
                }
              </mat-select>
            </mat-form-field>
          }
        </mat-card>

        <div class="actions">
          <button matButton="filled" (click)="save()" [disabled]="saving()" i18n="@@Save">Save</button>
        </div>
      </div>
    }
  `,
})
export class SecurityPageComponent {
  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);
  private readonly locale = inject(LOCALE_ID);

  protected human(iso: string): string {
    return humanDuration(iso, this.locale);
  }

  protected readonly loading = signal(true);
  protected readonly saving = signal(false);
  private readonly settings = signal<Settings | null>(null);

  protected readonly mfaRequired = signal(false);
  protected readonly rlLogin = signal(10);
  protected readonly rlTotp = signal(5);
  protected readonly rlWindow = signal('PT15M');
  protected readonly rlWindows = ['PT5M', 'PT15M', 'PT1H'];
  protected readonly passkeysAllowed = signal(true);
  protected readonly apiTokens = signal(true);
  protected readonly selfRegistration = signal(false);
  protected readonly selfRegisterCaptcha = signal(true);
  protected readonly trustAllowed = signal(false);
  protected readonly trustTtl = signal('P7D');
  protected readonly ttlChoices = TRUST_TTL_CHOICES;

  // Outbound e-mail (AUTH-20). The password field stays empty unless changed:
  // '' on save keeps the stored one (write-only server-side).
  protected readonly smtpHost = signal('');
  protected readonly smtpPort = signal(587);
  protected readonly smtpSecurity = signal('starttls');
  protected readonly smtpUsername = signal('');
  protected readonly smtpPassword = signal('');
  protected readonly smtpPasswordSet = signal(false);
  protected readonly smtpFrom = signal('');
  protected readonly smtpTestTo = signal('');

  constructor() {
    this.api.settings().subscribe({
      next: (s) => {
        this.settings.set(s);
        this.mfaRequired.set(s.mfaRequired);
        this.rlLogin.set(s.rateLimit?.loginAttempts ?? 10);
        this.rlTotp.set(s.rateLimit?.totpAttempts ?? 5);
        this.rlWindow.set(s.rateLimit?.loginWindow || 'PT15M');
        this.passkeysAllowed.set(s.passkeysAllowed);
        this.apiTokens.set(s.apiTokens);
        this.selfRegistration.set(s.selfRegistration);
        this.selfRegisterCaptcha.set(s.selfRegisterCaptcha);
        this.trustAllowed.set(s.trustedBrowser?.allowed ?? false);
        this.trustTtl.set(s.trustedBrowser?.ttl || 'P7D');
        this.smtpHost.set(s.smtp?.host ?? '');
        this.smtpPort.set(s.smtp?.port || 587);
        this.smtpSecurity.set(s.smtp?.security || 'starttls');
        this.smtpUsername.set(s.smtp?.username ?? '');
        this.smtpPasswordSet.set(s.smtp?.passwordSet ?? false);
        this.smtpFrom.set(s.smtp?.from ?? '');
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  protected save(then?: () => void): void {
    const s = this.settings();
    if (!s) return;
    this.saving.set(true);
    this.api
      .saveSettings({
        ...s,
        mfaRequired: this.mfaRequired(),
        rateLimit: { loginAttempts: this.rlLogin(), loginWindow: this.rlWindow(), totpAttempts: this.rlTotp() },
        passkeysAllowed: this.passkeysAllowed(),
        apiTokens: this.apiTokens(),
        selfRegistration: this.selfRegistration(),
        selfRegisterCaptcha: this.selfRegisterCaptcha(),
        trustedBrowser: { allowed: this.trustAllowed(), ttl: this.trustTtl() },
        smtp: {
          host: this.smtpHost().trim(),
          port: this.smtpPort() || 587,
          security: this.smtpSecurity(),
          username: this.smtpUsername().trim(),
          from: this.smtpFrom().trim(),
          password: this.smtpPassword(), // '' keeps the stored one
          passwordSet: this.smtpPasswordSet(),
        },
      })
      .subscribe({
        next: (saved) => {
          this.settings.set(saved);
          this.smtpPassword.set('');
          this.smtpPasswordSet.set(saved.smtp?.passwordSet ?? false);
          this.saving.set(false);
          this.snack.open($localize`:@@Settings_saved:Settings saved`, undefined, { duration: 2500 });
          then?.();
        },
        error: (err: unknown) => {
          this.saving.set(false);
          const e = err as { error?: { error?: string } };
          this.snack.open(
            typeof e?.error?.error === 'string' ? e.error.error : $localize`:@@Save_failed:Save failed`,
            undefined,
            { duration: 4000 },
          );
        },
      });
  }

  // Saves the whole page first, then fires one test message through the
  // stored config — what is verified is exactly what the flows will use.
  protected testSmtp(): void {
    this.save(() =>
      this.api.testSmtp(this.smtpTestTo().trim()).subscribe({
        next: ({ sent }) =>
          this.snack.open($localize`:@@Test_email_sent_to_ADDR:Test email sent to ${sent}:ADDR:`, undefined, {
            duration: 4000,
          }),
        error: (err: unknown) => {
          const e = err as { error?: { error?: string } };
          this.snack.open(
            typeof e?.error?.error === 'string' ? e.error.error : $localize`:@@Request_failed:Request failed`,
            undefined,
            { duration: 6000 },
          );
        },
      }),
    );
  }
}
