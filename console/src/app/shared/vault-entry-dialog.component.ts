import { Component, computed, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatButtonToggleModule } from '@angular/material/button-toggle';
import { MatInputModule } from '@angular/material/input';
import { FormFieldComponent } from './form-field.component';
import { ApiService, VaultEntry } from '../api.service';
import { VaultService } from './vault.service';

// Create or edit one vault entry. Opened from the vault page and, in one click,
// from any field offering the vault picker — so declaring a value never means
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
  protected readonly kinds = signal<('value' | 'secret')[]>(this.data.kinds?.length ? this.data.kinds : ['value', 'secret']);
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

  // A secret being edited may keep its stored value, so only a NEW entry
  // demands one here.
  protected readonly canSave = computed(
    () => /^[A-Za-z][A-Za-z0-9_.-]*$/.test(this.name().trim()) && (this.editing() || !!this.value()),
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
    this.api
      .saveVaultEntry({
        name: this.name().trim(),
        kind: this.kind(),
        scope: this.scope(),
        value: this.value(),
        description: this.description().trim(),
      })
      .subscribe({
        next: (saved) => {
          void this.vault.reload();
          this.saving.set(false);
          this.ref.close(saved);
        },
        error: (err: unknown) => {
          const e = err as { error?: { error?: string } };
          this.error.set(
            typeof e?.error?.error === 'string' ? e.error.error : $localize`:@@Save_failed:Save failed`,
          );
          this.saving.set(false);
        },
      });
  }
}
