import { Component, computed, inject, LOCALE_ID, signal } from '@angular/core';
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
const SESSION_TTL_CHOICES = ['PT15M', 'PT30M', 'PT1H', 'PT2H', 'PT4H', 'PT8H', 'PT12H', 'P1D'];

// Application-wide security policy (root only): how long a session lives, second
// factor (MFA-04), passkeys (AUTH-15), API tokens (AUTH-16), self-registration
// (AUTH-20), rate limiting (SEC-10), trusted browsers (MFA-03), and the outbound
// e-mail sender the account flows use. A full PUT of /api/settings - the other
// fields ride along untouched.
//
// The session TTL sits here, not on General: how long one stays signed in is a
// security policy, next to the second factor and the trusted browsers that gate
// the very same session.
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
  styleUrl: './security-page.component.scss',
  templateUrl: './security-page.component.html',
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
  // How many authorities are enabled, the local accounts included (AUTH-24).
  // Zero means nobody can sign in to the data plane at all, which the
  // self-registration hint below has to say.
  protected readonly authorities = signal(0);
  protected readonly selfRegisterCaptcha = signal(true);
  protected readonly trustAllowed = signal(false);
  protected readonly trustTtl = signal('P7D');
  protected readonly ttlChoices = TRUST_TTL_CHOICES;
  protected readonly sessionTTL = signal('');

  // The presets, plus whatever non-preset value the store already holds so the
  // select never silently drops it.
  protected readonly sessionTtlChoices = computed(() => {
    const current = this.sessionTTL();
    return current && !SESSION_TTL_CHOICES.includes(current)
      ? [current, ...SESSION_TTL_CHOICES]
      : SESSION_TTL_CHOICES;
  });

  // Outbound e-mail (AUTH-20): this plane owns the display name only.
  protected readonly smtpFromName = signal('');
  // Read-only: the relay, sender address included, belongs to the infra plane.
  protected readonly relayHost = signal('');
  protected readonly relayFrom = signal('');
  protected readonly relayConfigured = signal(false);

  // What the recipient reads once the name and the relay's address are joined.
  protected readonly preview = computed(() => {
    const addr = this.relayFrom();
    const name = this.smtpFromName().trim();
    return name ? `${name} <${addr}>` : addr;
  });

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
        this.authorities.set(s.authoritiesEnabled ?? 0);
        this.selfRegisterCaptcha.set(s.selfRegisterCaptcha);
        this.trustAllowed.set(s.trustedBrowser?.allowed ?? false);
        this.trustTtl.set(s.trustedBrowser?.ttl || 'P7D');
        this.sessionTTL.set(s.sessionTTL);
        this.smtpFromName.set(s.smtp?.fromName ?? '');
        this.relayHost.set(s.smtp?.relayHost ?? '');
        this.relayFrom.set(s.smtp?.relayFrom ?? '');
        this.relayConfigured.set(s.smtp?.relayConfigured ?? false);
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
        sessionTTL: this.sessionTTL().trim(),
        smtp: { fromName: this.smtpFromName().trim() },
      })
      .subscribe({
        next: (saved) => {
          this.settings.set(saved);
          this.relayHost.set(saved.smtp?.relayHost ?? '');
          this.relayFrom.set(saved.smtp?.relayFrom ?? '');
          this.relayConfigured.set(saved.smtp?.relayConfigured ?? false);
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
}
