import { Component, computed, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatChipsModule } from '@angular/material/chips';
import { MatDividerModule } from '@angular/material/divider';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatSnackBar } from '@angular/material/snack-bar';
import { Observable } from 'rxjs';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import {
  ApiService,
  BackupInfo,
  ConfigMissingRef,
  ConfigPlan,
  ConfigReport,
  ConfigSection,
} from '../api.service';

// What each gateway setting is about, in words rather than storage keys. Lazy
// so $localize runs at call time, with the locale already resolved.
const SETTING_LABELS: Record<string, () => string> = {
  business_access: () => $localize`:@@Setting_business_access:business hours`,
  session_ttl: () => $localize`:@@Setting_session_ttl:session lifetime`,
  branding: () => $localize`:@@Setting_branding:application identity`,
  languages: () => $localize`:@@Setting_languages:languages`,
  mfa_required: () => $localize`:@@Setting_mfa:second factor`,
  trusted_browser: () => $localize`:@@Setting_trusted_browser:trusted browsers`,
  registration: () => $localize`:@@Setting_registration:self-registration`,
  rate_limit: () => $localize`:@@Setting_rate_limit:rate limits`,
  api_tokens: () => $localize`:@@Setting_api_tokens:personal tokens`,
  passkeys_allowed: () => $localize`:@@Setting_passkeys:passkeys`,
  password_login: () => $localize`:@@Setting_password_login:password sign-in`,
  dev_docs_exposed: () => $localize`:@@Setting_dev_docs:developer docs`,
  issues_enabled: () => $localize`:@@Setting_issues:issue reporting`,
};

// Import and export of the whole configuration (CFG-03/05) - INFRA plane,
// root only.
//
// The screen is built around one promise: the file that leaves is PUBLIC. It
// says so, and it says what it left behind, before the download rather than
// after. On the way back in, nothing is applied until the admin has seen what
// would change and what the vault is missing - that preview is the last moment
// anyone remembers what a given $name was, which is why the entries are filled
// in right there.
@Component({
  selector: 'app-configuration-page',
  imports: [
    MatButtonModule,
    MatCardModule,
    MatCheckboxModule,
    MatChipsModule,
    MatDividerModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    LoadingIndicatorComponent,
  ],
  styles: [
    `
      :host {
        display: block;
        padding: 24px;
        max-width: 860px;
      }
      mat-card {
        padding: 20px 24px;
      }
      mat-card + mat-card {
        margin-top: 16px;
      }
      h1 {
        margin-top: 0;
      }
      h2 {
        margin: 0 0 4px;
        font-size: 1.05rem;
        font-weight: 500;
      }
      .hint {
        margin: 0 0 16px;
        font-size: 0.85rem;
        color: var(--mat-sys-on-surface-variant);
      }
      .hint:last-child {
        margin-bottom: 0;
      }
      .actions {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-top: 16px;
        flex-wrap: wrap;
      }
      .note {
        display: flex;
        gap: 12px;
        padding: 12px 16px;
        border-radius: 8px;
        background: var(--mat-sys-surface-container);
        margin-bottom: 16px;
      }
      .note mat-icon {
        flex-shrink: 0;
        color: var(--mat-sys-on-surface-variant);
      }
      .note.warn mat-icon {
        color: var(--mat-sys-error);
      }
      .note p {
        margin: 0;
        font-size: 0.85rem;
      }
      .note ul {
        margin: 6px 0 0;
        padding-left: 18px;
        font-size: 0.85rem;
      }
      .mono {
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      }
      table {
        width: 100%;
        border-collapse: collapse;
        font-size: 0.88rem;
      }
      td {
        padding: 6px 8px;
        border-top: 1px solid var(--mat-sys-outline-variant);
      }
      td.act {
        width: 92px;
      }
      td.kind {
        width: 120px;
        color: var(--mat-sys-on-surface-variant);
      }
      .add {
        color: var(--mat-sys-primary);
      }
      .remove {
        color: var(--mat-sys-error);
      }
      .same {
        color: var(--mat-sys-on-surface-variant);
      }
      .entry {
        display: flex;
        align-items: flex-start;
        gap: 12px;
      }
      .entry mat-form-field {
        flex: 1;
      }
      .entry button {
        margin-top: 8px;
      }
      .used {
        font-size: 0.78rem;
        color: var(--mat-sys-on-surface-variant);
      }
      .contents {
        margin: 0 0 16px;
        display: grid;
        grid-template-columns: max-content 1fr;
        gap: 4px 16px;
        font-size: 0.88rem;
      }
      .contents dt {
        color: var(--mat-sys-on-surface-variant);
        white-space: nowrap;
      }
      .contents dd {
        margin: 0;
      }
      .contents .absent {
        color: var(--mat-sys-on-surface-variant);
      }
      .file {
        display: flex;
        align-items: center;
        gap: 12px;
      }
      pre {
        margin: 8px 0 0;
        padding: 12px 16px;
        border-radius: 8px;
        background: var(--mat-sys-surface-container);
        font-size: 0.82rem;
        overflow-x: auto;
        white-space: pre;
      }
      .filename {
        font-size: 0.85rem;
        color: var(--mat-sys-on-surface-variant);
      }
    `,
  ],
  template: `
    <h1 i18n="@@Configuration">Configuration</h1>
    <p class="hint" i18n="@@Configuration_intro">
      Routes, roles, authorities, mail relay, themes and gateway settings travel as one file.
      Users, organisations, sessions and the vault stay where they are: they are not
      configuration, they are what this gateway lives with.
    </p>

    @if (loading()) {
      <loading-indicator withContainer />
    } @else {
      <mat-card appearance="outlined">
        <h2 i18n="@@Export">Export</h2>
        <p class="hint" i18n="@@Export_hint">
          A secret leaves as its vault reference or not at all, so the file is safe to put in a
          ticket or a git repository. Two exports of the same configuration are the same bytes,
          which is what makes the difference between two of them worth reading.
        </p>

        @if (report(); as r) {
          <!-- What KIND of thing is in the file, and what kind is not. Nobody
               should have to open an export to learn what it carries, and the
               second list is the one that reassures. -->
          @if (r.contents.length) {
            <dl class="contents">
              <dt i18n="@@It_carries">It carries</dt>
              <dd>{{ carried(r.contents) }}</dd>
              @if (settingKinds(r.contents); as kinds) {
                <dt i18n="@@Which_settings">Which settings</dt>
                <dd class="absent">{{ kinds }}</dd>
              }
              @if (imageWeight(r.contents); as weight) {
                <dt i18n="@@Image">Image</dt>
                <dd class="absent">
                  <ng-container i18n="@@The_application_logo">the application logo</ng-container>, {{ weight }}
                </dd>
              }
              <dt i18n="@@It_does_not_carry">It does not carry</dt>
              <dd class="absent" i18n="@@Not_carried_list">
                users, organisations and their members, sessions, the vault, the audit trail,
                personal tokens, signing keys
              </dd>
            </dl>
          }
          @if (r.literals.length) {
            <div class="note warn">
              <mat-icon>key_off</mat-icon>
              <div>
                <p i18n="@@Export_literals_note">
                  These secrets are stored here as values rather than vault references, so they
                  will NOT be in the file. Wherever it lands, the fields will be empty.
                </p>
                <ul>
                  @for (l of r.literals; track l.holder + l.id + l.field) {
                    <li>{{ l.label }} <span class="mono">{{ l.field }}</span></li>
                  }
                </ul>
              </div>
            </div>
          }
          @if (r.refs.length) {
            <div class="note">
              <mat-icon>vpn_key</mat-icon>
              <div>
                <p i18n="@@Export_refs_note2">
                  The file references these vault entries. On the other side, one that already
                  exists is used as it stands; one that is missing is created EMPTY and reported,
                  and whatever references it stays inert until someone fills it. Nothing is
                  overwritten and nothing blocks the import.
                </p>
                <mat-chip-set>
                  @for (name of r.refs; track name) {
                    <mat-chip disableRipple>{{ name }}</mat-chip>
                  }
                </mat-chip-set>
              </div>
            </div>
          }
        }

        <div class="actions">
          <button matButton="filled" (click)="download()" [disabled]="downloading()">
            <mat-icon>download</mat-icon>
            <ng-container i18n="@@Download_the_configuration">Download the configuration</ng-container>
          </button>
          @if (hasImage()) {
            <span class="hint" style="margin: 0" i18n="@@Downloads_as_a_package">
              A zip: the configuration reads and diffs, the logo sits beside it as a file.
            </span>
          }
        </div>
      </mat-card>

      <mat-card appearance="outlined">
        <h2 i18n="@@Import">Import</h2>
        <p class="hint" i18n="@@Import_hint">
          Nothing is applied before you have seen what would change. What the file does not
          mention is left alone, and a secret it does not carry keeps the one already stored.
        </p>

        <div class="file">
          <button matButton="outlined" (click)="picker.click()">
            <mat-icon>upload_file</mat-icon>
            <ng-container i18n="@@Choose_a_file">Choose a file</ng-container>
          </button>
          <input
            #picker
            type="file"
            accept=".yaml,.yml,.json,.zip,text/yaml,application/json,application/zip"
            hidden
            (change)="pick($event)"
          />
          @if (filename()) {
            <span class="filename mono">{{ filename() }}</span>
          }
        </div>

        <div class="actions">
          <mat-checkbox [checked]="prune()" (change)="setPrune($event.checked)">
            <ng-container i18n="@@Remove_what_the_file_does_not_mention">
              Remove what the file does not mention
            </ng-container>
          </mat-checkbox>
        </div>
        @if (prune()) {
          <p class="hint" i18n="@@Prune_hint">
            Only inside the sections the file actually carries: a file holding routes alone never
            touches the roles.
          </p>
        }

        @if (plan(); as p) {
          <mat-divider />
          @if (!touched()) {
            <div class="note">
              <mat-icon>check_circle</mat-icon>
              <p i18n="@@Nothing_would_change">
                This file describes what is already configured here. Importing it would change
                nothing.
              </p>
            </div>
          } @else {
            <table>
              @for (c of p.changes; track c.kind + c.id + c.label) {
                @if (c.action !== 'same') {
                  <tr>
                    <td class="act" [class]="c.action">{{ label(c.action) }}</td>
                    <td class="kind">{{ kindLabel(c.kind) }}</td>
                    <td>{{ c.label || c.id }}</td>
                  </tr>
                }
              }
            </table>
          }

          @if (p.missing.length) {
            <div class="note warn">
              <mat-icon>vpn_key_off</mat-icon>
              <div>
                <p i18n="@@Import_missing_note">
                  This configuration expects vault entries that do not exist here. They will be
                  created empty, and a route that references an empty entry does not serve until
                  it is filled.
                </p>
                <mat-chip-set>
                  @for (m of p.missing; track m.name) {
                    <mat-chip disableRipple>{{ m.name }}</mat-chip>
                  }
                </mat-chip-set>
              </div>
            </div>
          }

          <div class="actions">
            <button matButton="filled" (click)="apply()" [disabled]="importing()">
              <!-- No whitespace inside the branches: with preserveWhitespaces on,
                   an indented @if is several root nodes and the icon never reaches
                   matButton's icon slot (NG8011). -->
              @if (importing()) {<mat-icon spin>autorenew</mat-icon>} @else {<mat-icon>upload</mat-icon>}
              <ng-container i18n="@@Import_this_file">Import this file</ng-container>
            </button>
            <button matButton (click)="clear()" i18n="@@Cancel">Cancel</button>
          </div>
        }
      </mat-card>

      <mat-card appearance="outlined">
        <h2 i18n="@@Full_snapshot">Full snapshot</h2>
        <p class="hint" i18n="@@Snapshot_hint">
          A coherent copy of the whole database, taken while the gateway runs: routes and vault,
          but also users, organisations, sessions and the audit trail. This is what a backup
          restores; a configuration export is what a second gateway reproduces.
        </p>
        <div class="note">
          <mat-icon>schedule</mat-icon>
          <p i18n="@@Snapshot_scope_note">
            Meerkat takes the snapshot, because copying a live database with cp can catch it
            mid-write and nothing says so until the day you restore it. Scheduling, retention and
            shipping it off the host belong to your backup tool, not here.
          </p>
        </div>

        <div class="actions">
          <button matButton="filled" (click)="takeSnapshot()" [disabled]="snapshotting()">
            <!-- No whitespace inside the branches (NG8011). -->
            @if (snapshotting()) {<mat-icon spin>autorenew</mat-icon>} @else {<mat-icon>database</mat-icon>}
            <ng-container i18n="@@Download_a_snapshot">Download a snapshot</ng-container>
          </button>
          <button matButton (click)="showRestore.set(!showRestore())">
            <mat-icon>{{ showRestore() ? 'expand_less' : 'expand_more' }}</mat-icon>
            <ng-container i18n="@@How_to_restore">How to restore</ng-container>
          </button>
        </div>

        @if (showRestore()) {
          @if (backup(); as b) {
            <p class="hint" style="margin-top: 16px" i18n="@@Restore_hint">
              Restoring happens with the service stopped: a database cannot be replaced under the
              process holding it open, and the sessions and users it brings back are the ones the
              request doing it would depend on. Keep the old file until the new one has proven
              itself.
            </p>
            <pre>{{ restoreProcedure(b) }}</pre>
            @if (b.keyFromEnv) {
              <p class="hint" i18n="@@Key_from_env_note">
                The master key of this gateway comes from MEERKAT_VAULT_KEY, so it is not in that
                directory: the snapshot holds the vault encrypted and is worth nothing without
                that variable. Keep it that way.
              </p>
            } @else {
              <div class="note warn">
                <mat-icon>key</mat-icon>
                <p i18n="@@Key_beside_db_note">
                  The master key sits next to the database. Backing them up together undoes the
                  encryption at rest, exactly as a vault file stored beside its passphrase would:
                  keep the key in a secret manager, or supply it through MEERKAT_VAULT_KEY.
                </p>
              </div>
            }
          }
        }
      </mat-card>

      @if (toFill().length) {
        <mat-card appearance="outlined">
          <h2 i18n="@@Vault_entries_to_fill">Vault entries to fill</h2>
          <p class="hint" i18n="@@Vault_entries_to_fill_hint">
            The import created these empty. This is the moment to fill them: in a week nobody
            remembers what they were for.
          </p>
          @for (m of toFill(); track m.name) {
            <div class="entry">
              <mat-form-field>
                <mat-label>{{ m.name }}</mat-label>
                <input
                  matInput
                  [type]="m.kind === 'secret' ? 'password' : 'text'"
                  [value]="values()[m.name]"
                  (input)="setValue(m.name, $any($event.target).value)"
                  autocomplete="off"
                  spellcheck="false"
                />
                <!-- One root node, no surrounding whitespace: an indented @if is
                     several nodes and the hint never reaches its slot (NG8011). -->
                @if (m.used; as used) {<mat-hint><span class="used" i18n="@@Used_by_WHAT">Used by {{ used.join(', ') }}</span></mat-hint>}
              </mat-form-field>
              <button
                matButton="tonal"
                (click)="fill(m)"
                [disabled]="!values()[m.name].trim()"
                i18n="@@Save"
              >
                Save
              </button>
            </div>
          }
        </mat-card>
      }
    }
  `,
})
export class ConfigurationPageComponent {
  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);

  protected readonly loading = signal(true);
  protected readonly downloading = signal(false);
  protected readonly importing = signal(false);
  protected readonly report = signal<ConfigReport | null>(null);

  // The file the admin picked, kept AS IT IS: the same bytes are previewed and
  // then imported, so what was shown is what applies - and a package read as
  // text on the way would be corrupted.
  protected readonly file = signal<File | null>(null);
  protected readonly filename = signal('');
  protected readonly prune = signal(false);
  protected readonly plan = signal<ConfigPlan | null>(null);

  // The entries the import reserved empty, and what is being typed into them.
  protected readonly toFill = signal<ConfigMissingRef[]>([]);
  protected readonly values = signal<Record<string, string>>({});

  // The snapshot half (STORE-05).
  protected readonly snapshotting = signal(false);
  protected readonly showRestore = signal(false);
  protected readonly backup = signal<BackupInfo | null>(null);

  protected readonly touched = computed(
    () => this.plan()?.changes.some((c) => c.action !== 'same') ?? false,
  );

  constructor() {
    this.api.configReport().subscribe({
      next: (r) => {
        this.report.set(r);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
    this.api.backupInfo().subscribe({ next: (b) => this.backup.set(b) });
  }

  // A snapshot is a binary file: fetched as a Blob and handed straight to the
  // browser. Reading it as text would corrupt it silently.
  protected takeSnapshot(): void {
    this.snapshotting.set(true);
    this.api.snapshot().subscribe({
      next: (blob) => {
        this.snapshotting.set(false);
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `meerkat-${new Date().toISOString().slice(0, 10)}.db`;
        a.click();
        URL.revokeObjectURL(url);
      },
      error: (err: unknown) => {
        this.snapshotting.set(false);
        this.fail(err);
      },
    });
  }

  // The real paths of THIS installation, so the procedure is a copy-paste and
  // not a puzzle. The old file is kept aside: a restore one regrets must have a
  // way back.
  protected restoreProcedure(b: BackupInfo): string {
    return [
      '# 1. stop meerkat',
      '# 2. keep the current database aside',
      `mv ${b.dbFile} ${b.dbFile}.before-restore`,
      '# 3. put the snapshot in its place',
      `cp meerkat-YYYY-MM-DD.db ${b.dbFile}`,
      '# 4. start meerkat, then check a route and a sign-in',
    ].join('\n');
  }

  // "4 routes, 2 roles, the mail relay, 13 settings" - the NATURE of what is in
  // the file and how much of it, on one line. Which objects exactly is what the
  // file itself answers.
  protected carried(sections: ConfigSection[]): string {
    return sections
      .map((s) =>
        s.kind === 'mailRelay'
          ? this.family(s.kind, s.count)
          : `${s.count} ${this.family(s.kind, s.count).toLocaleLowerCase()}`,
      )
      .join(', ');
  }

  // The settings by NATURE. "12 settings" says nothing; what is configured is
  // exactly the question. Unknown keys fall back to themselves rather than
  // vanishing: a setting added server-side must show up here without waiting
  // for this list to be updated.
  protected settingKinds(sections: ConfigSection[]): string {
    const keys = sections.find((s) => s.kind === 'setting')?.keys ?? [];
    return keys.map((k) => SETTING_LABELS[k]?.() ?? k).join(', ');
  }

  // The logo is the only binary in the file and the only thing that can make it
  // heavy, so it is weighed out loud.
  protected imageWeight(sections: ConfigSection[]): string {
    const bytes = sections.find((s) => s.kind === 'image')?.bytes ?? 0;
    if (!bytes) return '';
    return bytes < 1024 ? `${bytes} B` : `${Math.round(bytes / 1024)} kB`;
  }

  // "3 routes", "1 role" - the plural is the count's business, not the label's.
  protected family(kind: string, count: number): string {
    const one = count === 1;
    switch (kind) {
      case 'route':
        return one ? $localize`:@@Route:Route` : $localize`:@@Routes:Routes`;
      case 'role':
        return one ? $localize`:@@Role:Role` : $localize`:@@Roles:Roles`;
      case 'authProvider':
        return one ? $localize`:@@Authority:Authority` : $localize`:@@Authorities:Authorities`;
      case 'theme':
        return one ? $localize`:@@Theme:Theme` : $localize`:@@Themes:Themes`;
      case 'mailRelay':
        return $localize`:@@Mail_relay:Mail relay`;
      default:
        return one ? $localize`:@@Setting:Setting` : $localize`:@@Settings:Settings`;
    }
  }

  // A package ONLY when there is an image to take out of the YAML: a zip
  // wrapping a single text file is a layer nobody asked for.
  protected readonly hasImage = computed(
    () => this.report()?.contents.some((c) => c.kind === 'image') ?? false,
  );

  protected download(): void {
    this.downloading.set(true);
    const packaged = this.hasImage();
    // One subscription for two shapes: a package comes back as bytes, a plain
    // configuration as text.
    const request: Observable<Blob | string> = packaged
      ? this.api.exportConfigBundle()
      : this.api.exportConfig();
    request.subscribe({
      next: (body: Blob | string) => {
        this.downloading.set(false);
        // Built here rather than pointed at the URL: the console talks to the
        // admin port with a session cookie, and a plain link would leave the
        // application to fetch it.
        const blob =
          typeof body === 'string' ? new Blob([body], { type: 'application/yaml' }) : body;
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = packaged ? 'meerkat-config.zip' : 'meerkat-config.yaml';
        a.click();
        URL.revokeObjectURL(url);
      },
      error: (err: unknown) => {
        this.downloading.set(false);
        this.fail(err);
      },
    });
  }

  protected pick(event: Event): void {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    input.value = ''; // so picking the same file twice fires again
    if (!file) return;
    this.file.set(file);
    this.filename.set(file.name);
    this.toFill.set([]);
    this.preview();
  }

  protected setPrune(on: boolean): void {
    this.prune.set(on);
    if (this.file()) this.preview();
  }

  private preview(): void {
    const file = this.file();
    if (!file) return;
    this.api.previewConfig(file, this.prune()).subscribe({
      next: (plan) => this.plan.set(plan),
      error: (err: unknown) => {
        this.plan.set(null);
        this.fail(err);
      },
    });
  }

  protected apply(): void {
    const file = this.file();
    if (!file) return;
    this.importing.set(true);
    this.api.importConfig(file, this.prune()).subscribe({
      next: (plan) => {
        this.importing.set(false);
        this.plan.set(null);
        this.file.set(null);
        this.filename.set('');
        this.expect(plan.missing ?? []);
        this.snack.open($localize`:@@Configuration_imported:Configuration imported`, undefined, {
          duration: 3000,
        });
        this.api.configReport().subscribe({ next: (r) => this.report.set(r) });
      },
      error: (err: unknown) => {
        this.importing.set(false);
        this.fail(err);
      },
    });
  }

  protected clear(): void {
    this.file.set(null);
    this.filename.set('');
    this.plan.set(null);
  }

  // Every reserved entry gets a key straight away: an input bound to a missing
  // key renders the string "undefined", which looks like a value and is not.
  private expect(entries: ConfigMissingRef[]): void {
    this.toFill.set(entries);
    this.values.set(Object.fromEntries(entries.map((m) => [m.name, ''])));
  }

  protected setValue(name: string, value: string): void {
    this.values.update((v) => ({ ...v, [name]: value }));
  }

  // Fills one reserved entry through the ordinary vault API: nothing special
  // happens here, the entry is simply no longer empty.
  protected fill(entry: ConfigMissingRef): void {
    const value = (this.values()[entry.name] || '').trim();
    if (!value) return;
    this.api
      .saveVaultEntry({ name: entry.name, scope: entry.scope, kind: entry.kind, value })
      .subscribe({
        next: () => {
          this.toFill.update((list) => list.filter((m) => m.name !== entry.name));
          this.snack.open($localize`:@@Saved:Saved`, undefined, { duration: 2000 });
        },
        error: (err: unknown) => this.fail(err),
      });
  }

  protected label(action: string): string {
    switch (action) {
      case 'add':
        return $localize`:@@Added:Added`;
      case 'update':
        return $localize`:@@Updated:Updated`;
      case 'remove':
        return $localize`:@@Removed:Removed`;
      default:
        return $localize`:@@Unchanged:Unchanged`;
    }
  }

  protected kindLabel(kind: string): string {
    switch (kind) {
      case 'route':
        return $localize`:@@Route:Route`;
      case 'role':
        return $localize`:@@Role:Role`;
      case 'authProvider':
        return $localize`:@@Authority:Authority`;
      case 'theme':
        return $localize`:@@Theme:Theme`;
      case 'mailRelay':
        return $localize`:@@Mail_relay:Mail relay`;
      default:
        return $localize`:@@Setting:Setting`;
    }
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
