import { Component, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatDialogModule, MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatSnackBar } from '@angular/material/snack-bar';
import { ApiService, VaultImportReport } from '../api.service';

export interface VaultFileDialogData {
  mode: 'export' | 'import';
}

// The vault as an encrypted file (VAULT-03): the passphrase dialog.
//
// This file is the opposite of a configuration export. It holds the values
// themselves, so it is encrypted, it is not something to version, and the
// passphrase is its ENTIRE security — one file concentrating every secret of an
// installation is the most rewarding target there is. Hence the generator: left
// to themselves, people type the product name and the year.
@Component({
  selector: 'app-vault-file-dialog',
  imports: [
    MatButtonModule,
    MatCheckboxModule,
    MatDialogModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
  ],
  styles: [
    `
      :host {
        display: block;
        max-width: 560px;
      }
      .hint {
        margin: 0 0 16px;
        font-size: 0.85rem;
        color: var(--mat-sys-on-surface-variant);
      }
      .row {
        display: flex;
        align-items: flex-start;
        gap: 8px;
      }
      .row mat-form-field {
        flex: 1;
      }
      .row button {
        margin-top: 8px;
      }
      .file {
        margin: 4px 0 16px;
        display: flex;
        align-items: center;
        gap: 12px;
      }
      .filename {
        font-size: 0.85rem;
        color: var(--mat-sys-on-surface-variant);
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      }
      .report {
        margin-top: 8px;
        font-size: 0.88rem;
      }
      .report div {
        padding: 3px 0;
      }
      .names {
        color: var(--mat-sys-on-surface-variant);
      }
      .warn {
        color: var(--mat-sys-error);
      }
    `,
  ],
  template: `
    <h2 mat-dialog-title>
      @if (data.mode === 'export') {
        <ng-container i18n="@@Export_the_vault">Export the vault</ng-container>
      } @else {
        <ng-container i18n="@@Import_a_vault">Import a vault</ng-container>
      }
    </h2>

    <mat-dialog-content>
      @if (data.mode === 'export') {
        <p class="hint" i18n="@@Vault_export_hint">
          Every entry you administer, encrypted under this passphrase. Unlike a configuration
          export, this file holds the values themselves: do not version it, and delete it once it
          has been used. Store the passphrase in a password manager: without it nobody reads the file, not even Meerkat.
        </p>
      } @else {
        <p class="hint" i18n="@@Vault_import_hint">
          An entry that is missing here is created, one that was left empty is filled, and one
          that already holds a different value is left alone unless you say otherwise.
        </p>
        <div class="file">
          <button matButton="outlined" (click)="picker.click()">
            <mat-icon>upload_file</mat-icon>
            <ng-container i18n="@@Choose_a_file">Choose a file</ng-container>
          </button>
          <input #picker type="file" accept=".json,application/json" hidden (change)="pick($event)" />
          @if (filename()) {
            <span class="filename">{{ filename() }}</span>
          }
        </div>
      }

      <div class="row">
        <mat-form-field>
          <mat-label i18n="@@Passphrase">Passphrase</mat-label>
          <input
            matInput
            [type]="reveal() ? 'text' : 'password'"
            [value]="passphrase()"
            (input)="passphrase.set($any($event.target).value)"
            autocomplete="off"
            spellcheck="false"
          />
          <!-- One root node, no surrounding whitespace: an indented @if is several
               nodes and the hint never reaches its slot (NG8011). -->
          @if (data.mode === 'export') {<mat-hint i18n="@@Passphrase_hint">At least 12 characters</mat-hint>}
        </mat-form-field>
        <button
          matIconButton
          (click)="reveal.set(!reveal())"
          i18n-aria-label="@@Show_hide"
          aria-label="Show or hide"
        >
          <mat-icon>{{ reveal() ? 'visibility_off' : 'visibility' }}</mat-icon>
        </button>
        @if (data.mode === 'export') {
          <button
            matButton="tonal"
            (click)="generate()"
            i18n="@@Generate"
          >
            Generate
          </button>
        }
      </div>

      @if (data.mode === 'import') {
        <mat-checkbox [checked]="overwrite()" (change)="overwrite.set($event.checked)">
          <ng-container i18n="@@Replace_entries_that_differ">
            Replace entries that already hold a different value
          </ng-container>
        </mat-checkbox>
      }

      @if (report(); as r) {
        <div class="report">
          @if (r.created.length) {
            <div>
              <ng-container i18n="@@N_created">{{ r.created.length }} created</ng-container>
              <span class="names">: {{ r.created.join(', ') }}</span>
            </div>
          }
          @if (r.filled.length) {
            <div>
              <ng-container i18n="@@N_filled">{{ r.filled.length }} filled</ng-container>
              <span class="names">: {{ r.filled.join(', ') }}</span>
            </div>
          }
          @if (r.replaced.length) {
            <div>
              <ng-container i18n="@@N_replaced">{{ r.replaced.length }} replaced</ng-container>
              <span class="names">: {{ r.replaced.join(', ') }}</span>
            </div>
          }
          @if (r.unchanged.length) {
            <div class="names" i18n="@@N_already_identical">
              {{ r.unchanged.length }} already identical
            </div>
          }
          @if (r.conflicts.length) {
            <div class="warn">
              <ng-container i18n="@@N_left_alone">
                {{ r.conflicts.length }} left alone: they already hold a different value
              </ng-container>
              <span class="names">: {{ r.conflicts.join(', ') }}</span>
            </div>
          }
          @if (r.skipped.length) {
            <div class="warn">
              <ng-container i18n="@@N_skipped">
                {{ r.skipped.length }} skipped: not yours to write, or an unknown organisation
              </ng-container>
              <span class="names">: {{ r.skipped.join(', ') }}</span>
            </div>
          }
        </div>
      }
    </mat-dialog-content>

    <mat-dialog-actions align="end">
      <button matButton (click)="ref.close()" i18n="@@Close">Close</button>
      @if (data.mode === 'export') {
        <button matButton="filled" (click)="download()" [disabled]="busy() || passphrase().length < 12">
          <mat-icon>download</mat-icon>
          <ng-container i18n="@@Download">Download</ng-container>
        </button>
      } @else {
        <button matButton="filled" (click)="upload()" [disabled]="busy() || !file() || !passphrase()">
          <mat-icon>upload</mat-icon>
          <ng-container i18n="@@Import">Import</ng-container>
        </button>
      }
    </mat-dialog-actions>
  `,
})
export class VaultFileDialogComponent {
  protected readonly ref = inject(MatDialogRef<VaultFileDialogComponent>);
  protected readonly data = inject<VaultFileDialogData>(MAT_DIALOG_DATA);
  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);

  protected readonly passphrase = signal('');
  protected readonly reveal = signal(false);
  protected readonly busy = signal(false);
  protected readonly overwrite = signal(false);
  protected readonly file = signal('');
  protected readonly filename = signal('');
  protected readonly report = signal<VaultImportReport | null>(null);

  // Long enough not to be guessed, short enough to survive a copy through a
  // terminal and a password manager. Minted in the BROWSER: a passphrase the
  // server proposes is a passphrase the server has seen.
  protected generate(): void {
    const raw = new Uint8Array(24);
    crypto.getRandomValues(raw);
    const b64 = btoa(String.fromCharCode(...raw))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    this.passphrase.set(b64);
    this.reveal.set(true);
    void navigator.clipboard?.writeText(b64).then(
      () =>
        this.snack.open($localize`:@@Passphrase_copied:Passphrase generated and copied`, undefined, {
          duration: 4000,
        }),
      () => undefined,
    );
  }

  protected pick(event: Event): void {
    const input = event.target as HTMLInputElement;
    const picked = input.files?.[0];
    input.value = '';
    if (!picked) return;
    void picked.text().then((text) => {
      this.file.set(text);
      this.filename.set(picked.name);
      this.report.set(null);
    });
  }

  protected download(): void {
    this.busy.set(true);
    this.api.exportVault(this.passphrase()).subscribe({
      next: (text) => {
        this.busy.set(false);
        const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
        const a = document.createElement('a');
        a.href = url;
        a.download = 'meerkat-vault.json';
        a.click();
        URL.revokeObjectURL(url);
        this.ref.close();
      },
      error: (err: unknown) => {
        this.busy.set(false);
        this.fail(err);
      },
    });
  }

  protected upload(): void {
    this.busy.set(true);
    this.api.importVault(this.file(), this.passphrase(), this.overwrite()).subscribe({
      next: (report) => {
        this.busy.set(false);
        this.report.set(report);
      },
      error: (err: unknown) => {
        this.busy.set(false);
        this.fail(err);
      },
    });
  }

  private fail(err: unknown): void {
    const e = err as { error?: { error?: string } };
    this.snack.open(
      typeof e?.error?.error === 'string' ? e.error.error : $localize`:@@Request_failed:Request failed`,
      undefined,
      { duration: 8000 },
    );
  }
}
