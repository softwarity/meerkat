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
import { EeLockComponent } from '../../shared/ee-lock.component';
import { ApiService, AuthProvider, SecretLocation } from '../../api.service';
import { DialogsService } from '../../shared/dialogs.service';
import { FormFieldComponent } from '../../shared/form-field.component';
import { SecretFieldComponent } from '../../shared/secret-field.component';
import { UrlInputComponent } from '../../shared/url-input.component';
import { isRef } from '../../shared/vault-ref';

// Which config field of each kind holds a secret. Mirrors idp.SecretFields:
// the server enforces it (a literal never comes back), this side is what tells
// the admin before they hit Save.
const SECRET_FIELDS: Record<string, string[]> = {
  oidc: ['clientSecret'],
  github: ['clientSecret'],
  ldap: ['bindPassword'],
  saml: [],
};

// The button name a kind writes itself. A VENDOR has one right answer and
// nobody should have to type it; a protocol has none — an OIDC authority is
// "Acme SSO" or "Partners", which only the admin knows.
const KIND_NAMES: Record<string, string> = {
  github: 'GitHub',
  oidc: '',
  ldap: '',
  saml: '',
};

// An identifier nobody should have to invent either: it is the URL segment a
// sign-in travels through (/login/<id>/callback), so it is derived — from the
// vendor when there is one, from the name otherwise — and only shown because
// it ends up in the address one registers with that vendor.
function slugify(s: string): string {
  return s
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40);
}

// github, then github-2: the second one of a kind is rare enough to deserve a
// suffix rather than a decision.
function freeId(wanted: string, taken: string[]): string {
  if (!wanted) return '';
  if (!taken.includes(wanted)) return wanted;
  for (let n = 2; ; n++) {
    const candidate = `${wanted}-${n}`;
    if (!taken.includes(candidate)) return candidate;
  }
}

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
    EeLockComponent,
    MatButtonModule,
    MatButtonToggleModule,
    MatDividerModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatSelectModule,
    MatSlideToggleModule,
    FormFieldComponent,
    SecretFieldComponent,
    UrlInputComponent,
  ],
  templateUrl: './auth-provider-editor.component.html',
  styleUrl: './auth-provider-editor.component.scss',
})
export class AuthProviderEditorComponent {
  // null creates one.
  readonly provider = input<AuthProvider | null>(null);
  // The identifiers already in use, so a derived one never collides.
  readonly takenIds = input<string[]>([]);

  readonly saved = output<AuthProvider>();
  readonly deleted = output<AuthProvider>();
  readonly closed = output<void>();

  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);
  private readonly dialogs = inject(DialogsService);

  protected readonly id = signal('');
  protected readonly kind = signal<'oidc' | 'ldap' | 'saml' | 'github'>('oidc');
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
  // Served by the server: the sign-in lands on the DATA plane, whose address
  // this console cannot deduce from its own. origin is what GitHub calls the
  // homepage URL, base ('http://host:8080/login/') what a callback is built on.
  protected readonly dataOrigin = signal('');
  private readonly callbackBase = signal('');
  // Name and identifier are DERIVED for a vendor — "GitHub" and github — so
  // they are not shown at all: two fields with one right answer are two ways
  // to get it wrong. Revealed on demand, for the second GitHub nobody has yet
  // needed. The identifier stays frozen after creation whatever happens: it is
  // in the URL registered with the vendor.
  protected readonly identityShown = signal(false);
  // Composed from the identifier as it is typed, so the address to paste into
  // the vendor's form is there DURING the creation — not after a first save,
  // which is when one has already left for the other tab. Falls back to what
  // the server computed for a stored authority.
  protected readonly callbackUrl = computed(() => {
    const id = this.id().trim();
    const base = this.callbackBase();
    if (base && id) return `${base}${encodeURIComponent(id)}/callback`;
    return this.provider()?.callbackUrl ?? '';
  });

  // A secret typed in clear blocks the save (VAULT-05). Only a typed one: a
  // literal the server already holds is its business to move, and blocking on
  // it would strand someone on a field whose value they cannot even see.
  private readonly typedSecret = computed(() =>
    (SECRET_FIELDS[this.kind()] ?? []).some((field) => {
      const v = this.cfg(field).trim();
      return !!v && !isRef(v);
    }),
  );

  protected readonly canSave = computed(
    () =>
      this.id().trim().length > 0 &&
      this.name().trim().length > 0 &&
      !this.saving() &&
      !this.typedSecret(),
  );

  // The server withheld this field's literal: it is set, but not in this page.
  protected secretHeld(field: string): boolean {
    return this.provider()?.secretsSet?.includes(field) ?? false;
  }

  // Where the server can find that literal to move it in on its own. The id
  // comes from the FORM so a brand-new authority still suggests a name.
  protected secretAt(field: string): SecretLocation {
    return { holder: 'authprovider', id: this.id().trim(), field };
  }

  constructor() {
    effect(() => {
      const p = this.provider();
      this.id.set(p?.id ?? '');
      // This editor configures a THIRD PARTY. The local accounts have nothing
      // to configure and their row opens nothing, so they never land here.
      this.kind.set(p && p.kind !== 'local' ? p.kind : 'oidc');
      this.name.set(p?.name ?? '');
      this.enabled.set(p?.enabled ?? false);
      this.autoCreate.set(p?.autoCreate ?? true);
      this.mfaRequired.set(p?.mfaRequired ?? '');
      this.passkeys.set(p?.passkeys ?? '');
      this.config.set({ ...(p?.config ?? {}) });
    });
    this.api.authCallbackBase().subscribe({
      next: ({ origin, base }) => {
        this.dataOrigin.set(origin);
        this.callbackBase.set(base);
      },
      // No base, no live URL: a stored authority still shows the one the
      // server computed, and nothing else breaks.
      error: () => {
        this.dataOrigin.set('');
        this.callbackBase.set('');
      },
    });
  }

  // The name is what the login page writes on the button, and for a vendor
  // there is only one right answer. Picking the kind fills it in — along with
  // the identifier, which is that same answer in URL form — and only while
  // both still hold something nobody chose: an "Acme SSO" typed by hand, or an
  // identifier unlocked on purpose, is never overwritten.
  protected pickKind(kind: 'oidc' | 'ldap' | 'saml' | 'github'): void {
    const suggested = KIND_NAMES[kind] ?? '';
    const current = this.name().trim();
    if (!current || Object.values(KIND_NAMES).includes(current)) this.name.set(suggested);
    this.kind.set(kind);
    this.deriveId();
  }

  // Typing a name for a protocol authority (no vendor to name it) feeds the
  // identifier as it goes: "Acme SSO" gives acme-sso.
  protected setName(value: string): void {
    this.name.set(value);
    this.deriveId();
  }

  private deriveId(): void {
    if (!this.creating() || this.identityShown()) return;
    const wanted = KIND_NAMES[this.kind()] ? this.kind() : slugify(this.name());
    this.id.set(freeId(wanted, this.takenIds()));
  }

  // Editing them is a deliberate act, hence the extra click.
  protected showIdentity(): void {
    this.identityShown.set(true);
  }

  // A kind that names itself (a vendor) needs neither field.
  protected readonly vendorKind = computed(() => !!KIND_NAMES[this.kind()]);
  protected readonly showName = computed(() => !this.vendorKind() || this.identityShown());

  // These addresses are derived from the one this gateway is reached by. Told
  // from a laptop, the vendor would be handed a localhost that only answers on
  // that laptop — which fails in production long after the setup, and looks
  // like the vendor's fault.
  protected readonly localOrigin = computed(() =>
    /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:|$)/.test(this.dataOrigin()),
  );

  // What has to be pasted into the VENDOR's form, under the vendor's own
  // labels. Handing over the values beats describing them: a first setup fails
  // on these addresses more often than on anything else, and every field the
  // admin retypes is a field they can mistype.
  protected readonly vendorFields = computed<{ label: string; value: string }[]>(() => {
    const callback = this.callbackUrl();
    if (!callback) return [];
    switch (this.kind()) {
      case 'github':
        return [
          { label: $localize`:@@Homepage_URL:Homepage URL`, value: this.dataOrigin() },
          { label: $localize`:@@Authorization_callback_URL:Authorization callback URL`, value: callback },
        ];
      case 'oidc':
      case 'saml':
        return [{ label: $localize`:@@Redirect_URI:Redirect URI`, value: callback }];
      default:
        return [];
    }
  });

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

  protected copy(text: string): void {
    void navigator.clipboard.writeText(text).then(() =>
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
