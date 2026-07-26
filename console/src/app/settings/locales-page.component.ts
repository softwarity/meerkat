import { Component, computed, inject, LOCALE_ID, signal } from '@angular/core';
import { MatAutocompleteModule } from '@angular/material/autocomplete';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatSnackBar } from '@angular/material/snack-bar';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import { ApiService, Settings } from '../api.service';

// The autocomplete's seed: common languages plus the usual regional variants.
const COMMON_LOCALES = [
  'ar', 'bg', 'cs', 'da', 'de', 'de-AT', 'de-CH', 'el', 'en', 'en-GB', 'en-US',
  'es', 'es-MX', 'et', 'fi', 'fr', 'fr-BE', 'fr-CA', 'fr-CH', 'he', 'hi', 'hr',
  'hu', 'id', 'it', 'ja', 'ko', 'lt', 'lv', 'nb', 'nl', 'nl-BE', 'pl', 'pt',
  'pt-BR', 'ro', 'ru', 'sk', 'sl', 'sr', 'sv', 'th', 'tr', 'uk', 'vi', 'zh',
  'zh-CN', 'zh-TW',
];

// Application locales (root only): the APPLICATION's own language pool, the
// master list from which routes pick and which flow pages speak (those Meerkat
// has embedded). It is its own Application entry on purpose: it is not a
// "general" knob, it is the application's identity. Empty by default (the flow
// pages then fall back to English). A full PUT of /api/settings; the other
// fields ride along untouched.
@Component({
  selector: 'app-locales-page',
  imports: [
    MatAutocompleteModule,
    MatButtonModule,
    MatCardModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    LoadingIndicatorComponent,
  ],
  styles: [
    `
      .banner {
        display: flex;
        align-items: center;
        gap: 16px;
        padding: 12px 24px;
      }
      .banner h1 {
        font-size: 1.15rem;
        font-weight: 500;
        margin: 0;
        flex: 1;
      }
      .content {
        padding: 0 24px 24px;
        display: grid;
        gap: 16px;
        max-width: 720px;
      }
      mat-card {
        padding: 16px 20px;
      }
      h3 {
        margin: 0 0 6px;
        font-size: 0.95rem;
        font-weight: 500;
      }
      .hint {
        margin: 0 0 12px;
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.85rem;
      }
      .field {
        width: 280px;
      }
      .actions {
        display: flex;
        justify-content: flex-end;
      }
      .lang-error {
        margin: 0 0 8px;
        color: var(--mat-sys-error);
        font-size: 0.85rem;
      }
      .locale-row {
        display: grid;
        grid-template-columns: 110px 1fr 1fr 40px;
        align-items: center;
        gap: 10px;
        padding: 2px 0 2px 4px;
        border-bottom: 1px solid var(--mat-sys-outline-variant);
      }
      .locale-row .lc {
        font-family: monospace;
        font-size: 0.85rem;
      }
      .locale-row .ln {
        color: var(--mat-sys-on-surface-variant);
      }
      .empty {
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.85rem;
        margin: 8px 0 0;
      }
    `,
  ],
  template: `
    @if (loading()) {
      <loading-indicator withContainer />
    } @else {
      <div class="banner">
        <h1 i18n="@@Locales">Locales</h1>
      </div>

      <div class="content">
        <mat-card appearance="outlined">
          <h3 i18n="@@Application_languages">Application languages</h3>
          <p class="hint" i18n="@@Languages_hint">
            The locales your APPLICATION supports (ISO codes like fr or fr-FR). They fill the
            flow pages and the user button, and the signed-in user's choice follows every
            proxied request. Empty leaves the flow pages in English.
          </p>
          <mat-form-field class="field">
            <mat-label i18n="@@Add_a_locale">Add a locale</mat-label>
            <input
              matInput
              placeholder="fr, en-US"
              [value]="newLocale()"
              (input)="newLocale.set($any($event.target).value)"
              (keydown.enter)="addLocale()"
              [matAutocomplete]="auto"
            />
          </mat-form-field>
          <mat-autocomplete #auto (optionSelected)="pick($event.option.value); $any($event.source).options.first?.deselect()">
            @for (o of localeOptions(); track o) {
              <mat-option [value]="o">{{ o }} · {{ localeName(o) }}</mat-option>
            }
          </mat-autocomplete>
          @if (localeError()) {
            <p class="lang-error">{{ localeError() }}</p>
          }
          @for (code of languages(); track code) {
            <div class="locale-row">
              <code class="lc">{{ code }}</code>
              <span>{{ localeName(code) }}</span>
              <span class="ln">{{ localeNative(code) }}</span>
              <button matIconButton (click)="removeLocale(code)" i18n-aria-label="@@Remove" aria-label="Remove">
                <mat-icon>delete</mat-icon>
              </button>
            </div>
          } @empty {
            <p class="empty" i18n="@@No_application_locale_yet">
              No application locale yet. The flow pages speak English.
            </p>
          }
        </mat-card>

        <div class="actions">
          <button matButton="filled" (click)="save()" [disabled]="saving()" i18n="@@Save">Save</button>
        </div>
      </div>
    }
  `,
})
export class LocalesPageComponent {
  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);
  private readonly locale = inject(LOCALE_ID);

  protected readonly loading = signal(true);
  protected readonly saving = signal(false);
  private readonly settings = signal<Settings | null>(null);

  protected readonly languages = signal<string[]>([]);
  protected readonly newLocale = signal('');
  protected readonly localeError = signal('');
  private readonly consoleNames = new Intl.DisplayNames([this.locale], { type: 'language' });

  protected readonly localeOptions = computed(() => {
    const q = this.newLocale().trim().toLowerCase();
    const taken = new Set(this.languages().map((c) => c.toLowerCase()));
    const base = COMMON_LOCALES.filter((c) => !taken.has(c.toLowerCase()));
    const matches = q
      ? base.filter((c) => c.toLowerCase().startsWith(q) || this.localeName(c).toLowerCase().includes(q))
      : base;
    let extra: string[] = [];
    try {
      const canon = q ? (Intl.getCanonicalLocales(q)[0] ?? '') : '';
      if (canon && !taken.has(canon.toLowerCase()) && !matches.some((c) => c.toLowerCase() === canon.toLowerCase())) {
        const label = new Intl.DisplayNames(['en'], { type: 'language' }).of(canon);
        if (label && label !== canon) extra = [canon];
      }
    } catch {
      // not a parseable code yet; suggestions alone
    }
    return [...extra, ...matches].slice(0, 12);
  });

  protected pick(code: string): void {
    this.newLocale.set('');
    this.localeError.set('');
    if (!this.languages().some((c) => c.toLowerCase() === code.toLowerCase())) {
      this.languages.update((list) => [...list, code]);
    }
  }

  protected localeName(code: string): string {
    try {
      const n = this.consoleNames.of(code) ?? code;
      return n.charAt(0).toUpperCase() + n.slice(1);
    } catch {
      return code;
    }
  }

  protected localeNative(code: string): string {
    try {
      const n = new Intl.DisplayNames([code], { type: 'language' }).of(code) ?? code;
      return n.charAt(0).toUpperCase() + n.slice(1);
    } catch {
      return code;
    }
  }

  protected addLocale(): void {
    const raw = this.newLocale().trim();
    if (!raw) return;
    let canon = '';
    try {
      canon = Intl.getCanonicalLocales(raw)[0] ?? '';
      const label = new Intl.DisplayNames(['en'], { type: 'language' }).of(canon);
      if (!label || label === canon) canon = '';
    } catch {
      canon = '';
    }
    if (!canon) {
      this.localeError.set($localize`:@@CODE_is_not_a_valid_ISO_code:"${raw}:CODE:" is not a valid ISO code`);
      return;
    }
    if (this.languages().some((c) => c.toLowerCase() === canon.toLowerCase())) {
      this.localeError.set($localize`:@@CODE_is_already_listed:"${canon}:CODE:" is already listed`);
      return;
    }
    this.localeError.set('');
    this.newLocale.set('');
    this.languages.update((list) => [...list, canon]);
  }

  // Empty is allowed: the flow pages fall back to English.
  protected removeLocale(code: string): void {
    this.languages.update((list) => list.filter((c) => c !== code));
  }

  constructor() {
    this.api.settings().subscribe({
      next: (s) => {
        this.settings.set(s);
        this.languages.set(s.languages ?? []);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  protected save(): void {
    const s = this.settings();
    if (!s) return;
    this.saving.set(true);
    this.api
      .saveSettings({ ...s, languages: this.languages() })
      .subscribe({
        next: (saved) => {
          this.settings.set(saved);
          this.saving.set(false);
          this.snack.open($localize`:@@Settings_saved:Settings saved`, undefined, { duration: 2500 });
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
