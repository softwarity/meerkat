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
  styles: [
    `
      :host {
        display: block;
        /* Fixed, not min-: a content-driven width made the dialog jump
           horizontally when the hint text changed length. */
        width: min(520px, 86vw);
      }
      app-form-field {
        display: block;
        width: 100%;
        margin-bottom: 6px;
      }
      /* Fixed height: switching value <-> secret swaps this text, and the
         dialog must not jump under the pointer. */
      .hint {
        margin: 0 0 14px;
        min-height: 2.6em;
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.82rem;
      }
      /* One line, never resizable: a textarea looks like an input here but is
         not a candidate for the browser's credential autofill. Spell-checking
         is turned off on each one: a secret or an entry name is not prose, and
         the red squiggles were pure noise. */
      .oneline {
        resize: none;
        overflow: hidden;
        white-space: nowrap;
      }
      .rowtop {
        display: flex;
        align-items: center;
        gap: 12px;
        flex-wrap: wrap;
        margin-bottom: 4px;
      }
      .err {
        color: var(--mat-sys-error);
        font-size: 0.85rem;
        white-space: pre-wrap;
      }
    `,
  ],
  template: `
    <h2 mat-dialog-title>
      @if (editing()) {
        <ng-container i18n="@@Edit_vault_entry">Edit entry</ng-container>
      } @else {
        <ng-container i18n="@@New_vault_entry">New entry</ng-container>
      }
    </h2>
    <mat-dialog-content>
      <div class="rowtop">
        @if (kinds().length > 1) {
          <mat-button-toggle-group
            class="kinds"
            [value]="kind()"
            (change)="kind.set($event.value)"
            hideSingleSelectionIndicator
          >
            <mat-button-toggle value="value" i18n="@@Kind_value">Value</mat-button-toggle>
            <mat-button-toggle value="secret" i18n="@@Kind_secret">Secret</mat-button-toggle>
          </mat-button-toggle-group>
        }
        @if (scopes().length > 1) {
          <mat-button-toggle-group
            [value]="scope()"
            (change)="scope.set($event.value)"
            [disabled]="editing()"
            hideSingleSelectionIndicator
          >
            @for (sc of scopes(); track sc) {
              <mat-button-toggle [value]="sc">{{ scopeLabel(sc) }}</mat-button-toggle>
            }
          </mat-button-toggle-group>
        }
      </div>
      <p class="hint">
        @if (kind() === 'secret') {
          <ng-container i18n="@@Kind_secret_hint">
            Encrypted at rest and never shown again. Referenced by $name wherever it is needed.
          </ng-container>
        } @else {
          <ng-container i18n="@@Kind_value_hint">
            Stored in clear and readable. Referenced by $name wherever it is needed.
          </ng-container>
        }
      </p>

      <app-form-field
        i18n-label="@@Name"
        label="Name"
        i18n-hint="@@Vault_name_hint"
        hint="A letter, then letters, digits, dot, dash or underscore"
      >
        <textarea
          matInput
          rows="1"
          class="oneline"
          spellcheck="false"
          autocapitalize="off"
          autocorrect="off"
          [value]="name()"
          [disabled]="editing()"
          (input)="name.set($any($event.target).value)"
          (keydown.enter)="$event.preventDefault()"
          placeholder="api-host"
        ></textarea>
      </app-form-field>

      <app-form-field
        i18n-label="@@Value"
        label="Value"
        [revealable]="kind() === 'secret'"
        [masked]="kind() === 'secret'"
        [clearable]="false"
        [hint]="keepHint()"
      >
        <textarea
          matInput
          rows="1"
          class="oneline"
          spellcheck="false"
          autocapitalize="off"
          autocorrect="off"
          [value]="value()"
          (input)="value.set($any($event.target).value)"
          (keydown.enter)="$event.preventDefault()"
        ></textarea>
      </app-form-field>

      <app-form-field i18n-label="@@Description" label="Description">
        <textarea
          matInput
          rows="1"
          class="oneline"
          spellcheck="false"
          autocapitalize="off"
          autocorrect="off"
          [value]="description()"
          (input)="description.set($any($event.target).value)"
          (keydown.enter)="$event.preventDefault()"
        ></textarea>
      </app-form-field>

      @if (error(); as e) {
        <p class="err">{{ e }}</p>
      }
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button matButton mat-dialog-close i18n="@@Cancel">Cancel</button>
      <button matButton="filled" [disabled]="!canSave() || saving()" (click)="save()" i18n="@@Save">Save</button>
    </mat-dialog-actions>
  `,
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
