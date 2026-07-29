import { Component, computed, effect, inject, input, output, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatButtonToggleModule } from '@angular/material/button-toggle';
import { MatDividerModule } from '@angular/material/divider';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatSnackBar } from '@angular/material/snack-bar';
import { ApiService, AuthProvider } from '../../api.service';
import { DialogsService } from '../../shared/dialogs.service';
import { FormFieldComponent } from '../../shared/form-field.component';

// One external authority, in the right drawer of the authorities page. The
// form follows the KIND: an OIDC provider and a directory share almost
// nothing, and pretending otherwise would mean fifteen fields of which four
// apply.
//
// Secrets are meant to be $name vault references rather than literals, which
// is why every credential field offers the vault picker.
@Component({
  selector: 'app-auth-provider-editor',
  imports: [
    MatButtonModule,
    MatButtonToggleModule,
    MatDividerModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatSelectModule,
    MatSlideToggleModule,
    FormFieldComponent,
  ],
  templateUrl: './auth-provider-editor.component.html',
  styleUrl: './auth-provider-editor.component.scss',
})
export class AuthProviderEditorComponent {
  // null creates one.
  readonly provider = input<AuthProvider | null>(null);

  readonly saved = output<AuthProvider>();
  readonly deleted = output<AuthProvider>();
  readonly closed = output<void>();

  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);
  private readonly dialogs = inject(DialogsService);

  protected readonly id = signal('');
  protected readonly kind = signal<'oidc' | 'ldap' | 'saml'>('oidc');
  protected readonly name = signal('');
  protected readonly enabled = signal(false);
  protected readonly autoCreate = signal(true);
  protected readonly mfaRequired = signal('');
  protected readonly passkeys = signal('');
  protected readonly saving = signal(false);
  protected readonly checking = signal(false);

  // The kind-specific fields, kept as one bag so adding a field is one line
  // in the template and nothing here.
  protected readonly config = signal<Record<string, unknown>>({});

  protected readonly creating = computed(() => this.provider() === null);
  protected readonly callbackUrl = computed(() => this.provider()?.callbackUrl ?? '');
  protected readonly canSave = computed(
    () => this.id().trim().length > 0 && this.name().trim().length > 0 && !this.saving(),
  );

  constructor() {
    effect(() => {
      const p = this.provider();
      this.id.set(p?.id ?? '');
      this.kind.set(p?.kind ?? 'oidc');
      this.name.set(p?.name ?? '');
      this.enabled.set(p?.enabled ?? false);
      this.autoCreate.set(p?.autoCreate ?? true);
      this.mfaRequired.set(p?.mfaRequired ?? '');
      this.passkeys.set(p?.passkeys ?? '');
      this.config.set({ ...(p?.config ?? {}) });
    });
  }

  // cfg/setCfg keep the template honest: one accessor pair for every
  // kind-specific field, whatever its name.
  protected cfg(key: string): string {
    const v = this.config()[key];
    if (Array.isArray(v)) return v.join(', ');
    return v === undefined || v === null ? '' : String(v);
  }

  protected setCfg(key: string, value: string): void {
    this.config.update((c) => ({ ...c, [key]: value }));
  }

  // A comma-separated field that the server wants as a list.
  protected setCfgList(key: string, value: string): void {
    const list = value
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    this.config.update((c) => ({ ...c, [key]: list }));
  }

  protected cfgBool(key: string, def = false): boolean {
    const v = this.config()[key];
    return typeof v === 'boolean' ? v : def;
  }

  protected setCfgBool(key: string, value: boolean): void {
    this.config.update((c) => ({ ...c, [key]: value }));
  }

  private current(): AuthProvider {
    return {
      id: this.id().trim(),
      kind: this.kind(),
      name: this.name().trim(),
      enabled: this.enabled(),
      order: this.provider()?.order ?? 0,
      config: this.config(),
      mfaRequired: this.mfaRequired(),
      passkeys: this.passkeys(),
      autoCreate: this.autoCreate(),
    };
  }

  protected save(): void {
    if (!this.canSave()) return;
    this.saving.set(true);
    this.api.saveAuthProvider(this.current()).subscribe({
      next: (p) => {
        this.saving.set(false);
        this.saved.emit(p);
      },
      error: (err: unknown) => {
        this.saving.set(false);
        this.fail(err);
      },
    });
  }

  // Tries the configuration without signing anyone in: the fastest way to
  // learn that the issuer does not resolve or the service account cannot bind.
  protected check(): void {
    const p = this.provider();
    if (!p) return;
    this.checking.set(true);
    this.api.checkAuthProvider(p.id).subscribe({
      next: () => {
        this.checking.set(false);
        this.snack.open($localize`:@@Provider_reachable:The authority answered`, undefined, { duration: 3000 });
      },
      error: (err: unknown) => {
        this.checking.set(false);
        this.fail(err, 6000);
      },
    });
  }

  protected async remove(): Promise<void> {
    const p = this.provider();
    if (!p) return;
    const ok = await this.dialogs.confirm({
      title: $localize`:@@Delete_provider_NAME:Delete "${p.name}:NAME:"?`,
      // Deleting strands the accounts that only came in this way.
      message: $localize`:@@Delete_provider_hint:The accounts that sign in through it will keep existing, but will no longer have a way in.`,
      confirmLabel: $localize`:@@Delete:Delete`,
      danger: true,
    });
    if (!ok) return;
    this.api.deleteAuthProvider(p.id).subscribe({
      next: () => this.deleted.emit(p),
      error: (err: unknown) => this.fail(err),
    });
  }

  protected copyCallback(): void {
    void navigator.clipboard.writeText(this.callbackUrl()).then(() =>
      this.snack.open($localize`:@@Copied:Copied`, undefined, { duration: 1500 }),
    );
  }

  private fail(err: unknown, duration = 4000): void {
    const e = err as { error?: { error?: string } };
    this.snack.open(
      typeof e?.error?.error === 'string' ? e.error.error : $localize`:@@Request_failed:Request failed`,
      undefined,
      { duration },
    );
  }
}
