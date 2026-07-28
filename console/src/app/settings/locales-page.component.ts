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
  styleUrl: './locales-page.component.scss',
  templateUrl: './locales-page.component.html',
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
