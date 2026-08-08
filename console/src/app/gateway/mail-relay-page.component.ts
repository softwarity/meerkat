import { Component, computed, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatRadioModule } from '@angular/material/radio';
import { MatCardModule } from '@angular/material/card';
import { MatDividerModule } from '@angular/material/divider';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatSnackBar } from '@angular/material/snack-bar';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import { ApiService, MailRelay } from '../api.service';
import { MeService } from '../me.service';
import { FormFieldComponent } from '../shared/form-field.component';
import { SecretFieldComponent } from '../shared/secret-field.component';
import { isRef } from '../shared/vault-ref';

// Enough to catch a typo, not to rule on RFC 5322: the relay itself is the real
// judge, and the point here is only to stop a pointless round-trip.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// The mail relay (AUTH-20) - INFRA plane. A third-party service reached by host
// and port, with credentials: the same nature as a route's upstream, and the
// reason it does not sit with the application settings. What the recipient
// sees, the sender address, belongs to the application (Security page).
@Component({
  selector: 'app-mail-relay-page',
  imports: [
    MatButtonModule,
    MatCardModule,
    MatDividerModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatRadioModule,
    MatSelectModule,
    LoadingIndicatorComponent,
    FormFieldComponent,
    SecretFieldComponent,
  ],
  styleUrl: './mail-relay-page.component.scss',
  templateUrl: './mail-relay-page.component.html',
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
  // The authentication mode: 'password' or 'oauth2'. Two modes, two forms.
  protected readonly auth = signal('password');
  protected readonly tokenUrl = signal('');
  protected readonly clientId = signal('');
  protected readonly clientSecret = signal('');
  protected readonly clientSecretSet = signal(false);
  protected readonly scope = signal('');
  protected readonly from = signal('');
  // The display name comes from the application plane: shown, never edited.
  protected readonly fromName = signal('');
  protected readonly testTo = signal('');

  // The sender address has two cases, and they call for opposite advice.
  // When the account IS an address, providers send as that one and little
  // else, so an empty field is the right answer. When it is not (an api key,
  // an SES identifier), an address is required, and it has to be one the
  // provider has verified or the mail is refused or lands in spam.
  protected readonly fromHint = computed(() =>
    this.username().includes('@')
      ? $localize`:@@Sender_address_hint_account:Empty sends as the account. Most providers accept only that address, or a verified alias.`
      : $localize`:@@Sender_address_hint_key:The account is not an address, so one is required here. It must be verified with the provider.`,
  );

  // A secret typed in clear blocks Save and Test (VAULT-05), whichever mode
  // holds it. Judged here rather than through a template reference: the fields
  // live in branches now, and a reference inside one is invisible outside it.
  protected readonly typedSecret = computed(() => {
    const typed = (v: string) => !!v.trim() && !isRef(v);
    return this.auth() === 'oauth2' ? typed(this.clientSecret()) : typed(this.password());
  });

  // Nothing to send to, nothing to test: the button stays off until the address
  // is at least shaped like one.
  protected readonly recipientOK = computed(() => EMAIL_RE.test(this.testTo().trim()));

  // The address that will actually be used: the explicit one, or the account
  // when it is an e-mail (most providers only accept that one anyway).
  protected readonly effectiveFrom = computed(() => {
    const explicit = this.from().trim();
    if (explicit) return explicit;
    const user = this.username().trim();
    return user.includes('@') ? user : '';
  });

  // What the recipient will read, once the application's display name is put
  // in front of the address.
  protected readonly senderPreview = computed(() => {
    const addr = this.effectiveFrom();
    if (!addr) return '';
    const name = this.fromName().trim();
    return name ? `${name} <${addr}>` : addr;
  });

  constructor() {
    // One's own address is the obvious recipient: prefill it, so testing a relay
    // is one click.
    this.testTo.set(this.me.user()?.email ?? '');
    this.reload();
  }

  // Also called after a secret is moved into the vault: that move rewrites the
  // relay SERVER-SIDE, so what this page holds is stale.
  protected reload(): void {
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
    this.from.set(r.from ?? '');
    this.fromName.set(r.fromName ?? '');
    // A REFERENCE comes back and is shown; a literal never does, and only
    // raises passwordSet. The two are exclusive, which is what lets the field
    // tell "points at the vault" from "holds something we cannot see".
    this.password.set(r.password ?? '');
    this.passwordSet.set(!!r.passwordSet);
    this.auth.set(r.auth || 'password');
    this.tokenUrl.set(r.oauth2?.tokenUrl ?? '');
    this.clientId.set(r.oauth2?.clientId ?? '');
    this.clientSecret.set(r.oauth2?.clientSecret ?? '');
    this.clientSecretSet.set(!!r.oauth2SecretSet);
    this.scope.set(r.oauth2?.scope ?? '');
  }

  // The relay as the form has it right now - what both Save and Test act on.
  private current(): MailRelay {
    return {
      host: this.host().trim(),
      port: this.port() || 587,
      security: this.security(),
      username: this.username().trim(),
      password: this.password(), // '' keeps the stored one
      from: this.from().trim(), // '' sends as the account, when it is an address
      auth: this.auth(),
      oauth2: {
        tokenUrl: this.tokenUrl().trim(),
        clientId: this.clientId().trim(),
        clientSecret: this.clientSecret(), // '' keeps the stored one
        scope: this.scope().trim(),
      },
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
