import { Component, computed, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatButtonToggleModule } from '@angular/material/button-toggle';
import { MatInputModule } from '@angular/material/input';
import { FormFieldComponent } from './form-field.component';
import { ApiService, SecretLocation, VaultEntry } from '../api.service';
import { VaultService } from './vault.service';

// Create or edit one vault entry. Opened from the vault page and, in one click,
// from any field offering the vault picker - so declaring a value never means
// leaving the screen you are configuring.
export interface VaultEntryDialogData {
  // The entry to edit; absent creates one.
  entry?: VaultEntry;
  // Restricts the kind when the caller only accepts one (a password field has
  // no use for a plain value).
  kinds?: ('value' | 'secret')[];
  // Prefills the name (from the field being configured).
  suggestedName?: string;
  // Restricts the scope, when the caller knows it (a route field is gateway,
  // an application setting is app).
  scopes?: string[];
  // Display names for tenant scopes ("tenant:<id>" -> the org name).
  tenantNames?: Record<string, string>;
  // Moving a secret that ALREADY exists into the vault, rather than declaring
  // a new one. The value is never asked for here: either the field hands over
  // the literal that was just typed, or the server takes the one it holds and
  // the console never sees it at all.
  stash?: {
    value?: string;
    from?: SecretLocation;
  };
}

@Component({
  selector: 'app-vault-entry-dialog',
  imports: [
    MatButtonModule,
    MatButtonToggleModule,
    MatDialogModule,
    MatInputModule,
    FormFieldComponent,
  ],
  styleUrl: './vault-entry-dialog.component.scss',
  templateUrl: './vault-entry-dialog.component.html',
})
export class VaultEntryDialogComponent {
  private readonly api = inject(ApiService);
  private readonly vault = inject(VaultService);
  private readonly ref = inject(MatDialogRef<VaultEntryDialogComponent, VaultEntry>);
  private readonly data = inject<VaultEntryDialogData>(MAT_DIALOG_DATA, { optional: true }) ?? {};

  protected readonly editing = signal(!!this.data.entry);
  // Moving an existing secret in: no kind to pick (it is one), no value to
  // type (it exists), only where to file it.
  protected readonly stashing = signal(!!this.data.stash);
  protected readonly kinds = signal<('value' | 'secret')[]>(
    this.stashing() ? ['secret'] : this.data.kinds?.length ? this.data.kinds : ['value', 'secret'],
  );
  protected readonly kind = signal<'value' | 'secret'>(this.data.entry?.kind ?? this.kinds()[0]);
  // The planes this admin may write to; a single one needs no chooser.
  protected readonly scopes = signal<string[]>(
    this.data.scopes?.length ? this.data.scopes : ['infra', 'app'],
  );
  protected readonly scope = signal<string>(this.data.entry?.scope ?? this.scopes()[0]);
  protected readonly name = signal(this.data.entry?.name ?? this.data.suggestedName ?? '');
  protected readonly value = signal(this.data.entry?.value ?? '');
  protected readonly description = signal(this.data.entry?.description ?? '');
  protected readonly saving = signal(false);
  protected readonly error = signal('');

  // Editing a secret may leave the value empty to keep the stored one.
  protected readonly keepHint = computed(() =>
    this.editing() && this.kind() === 'secret'
      ? $localize`:@@Secret_keep_hint:Leave empty to keep the stored secret`
      : '',
  );

  // A secret being edited may keep its stored value, and one being moved in
  // already has one, so only a NEW entry demands a value here.
  protected readonly canSave = computed(
    () =>
      /^[A-Za-z][A-Za-z0-9_.-]*$/.test(this.name().trim()) &&
      (this.editing() || this.stashing() || !!this.value()),
  );

  // "gateway" / "app" read as themselves; a tenant scope shows the org name.
  protected scopeLabel(scope: string): string {
    if (scope === 'infra') return $localize`:@@Scope_infra:Infra`;
    if (scope === 'app') return $localize`:@@Scope_app:Application`;
    return this.data.tenantNames?.[scope] ?? scope.replace('tenant:', '');
  }

  protected save(): void {
    this.saving.set(true);
    this.error.set('');
    const stash = this.data.stash;
    // A secret the server holds is moved BY the server: the value stays where
    // it is and only the reference comes back.
    if (stash?.from) {
      this.api.stashSecret(stash.from, this.name().trim(), this.description().trim()).subscribe({
        next: ({ name, scope }) => {
          void this.vault.reload();
          this.saving.set(false);
          this.ref.close({ name, scope, kind: 'secret' } as VaultEntry);
        },
        error: (err: unknown) => this.failed(err),
      });
      return;
    }
    this.api
      .saveVaultEntry({
        name: this.name().trim(),
        kind: this.kind(),
        scope: this.scope(),
        // Moving a typed literal in: the field hands it over here, and this is
        // the last place it exists outside the vault.
        value: stash?.value ?? this.value(),
        description: this.description().trim(),
      })
      .subscribe({
        next: (saved) => {
          void this.vault.reload();
          this.saving.set(false);
          this.ref.close(saved);
        },
        error: (err: unknown) => this.failed(err),
      });
  }

  private failed(err: unknown): void {
    const e = err as { error?: { error?: string } };
    this.error.set(
      typeof e?.error?.error === 'string' ? e.error.error : $localize`:@@Save_failed:Save failed`,
    );
    this.saving.set(false);
  }
}
