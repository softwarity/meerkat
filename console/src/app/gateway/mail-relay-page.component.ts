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
  protected readonly testTo = signal('');

  // The stored password is never sent back, so the field looks empty even when
  // one is set: say so under it, and say what an empty field will do on save.
  protected readonly passwordHint = computed(() => {
    if (this.password()) return $localize`:@@Replaces_the_stored_password:Replaces the stored password`;
    return this.passwordSet()
      ? $localize`:@@A_password_is_stored_leave_empty_to_keep_it:A password is stored. Leave empty to keep it.`
      : $localize`:@@No_password_stored:No password stored`;
  });

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
