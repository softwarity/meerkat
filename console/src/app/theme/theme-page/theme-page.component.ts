import { Component, computed, inject, signal } from '@angular/core';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatSnackBar } from '@angular/material/snack-bar';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import { MatRadioModule } from '@angular/material/radio';
import { ApiService, Settings, Theme } from '../../api.service';
import { DialogsService } from '../../shared/dialogs.service';
import { BrandingCardComponent } from '../branding-card/branding-card.component';
import { PaletteEditorComponent } from '../palette-editor/palette-editor.component';
import { ThemeCarouselComponent } from '../theme-carousel/theme-carousel.component';
import { ThemePreviewComponent } from '../theme-preview/theme-preview.component';
import { CSS_VARS } from '../theme-tokens';

// Theme administration (THEME-04, root): several saved themes, one active;
// branding (THEME-02) edited alongside. This shell owns the state and the API
// calls; the sub-components do the work.
@Component({
  selector: 'app-theme-page',
  imports: [
    MatCardModule,
    MatRadioModule,
    MatFormFieldModule,
    MatSelectModule,
    LoadingIndicatorComponent,
    BrandingCardComponent,
    PaletteEditorComponent,
    ThemePreviewComponent,
    ThemeCarouselComponent,
  ],
  templateUrl: './theme-page.component.html',
  styleUrl: './theme-page.component.scss',
})
export class ThemePageComponent {
  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);
  private readonly dialogs = inject(DialogsService);

  protected readonly loading = signal(true);
  protected readonly saving = signal(false);
  protected readonly themes = signal<Theme[]>([]);
  protected readonly presets = signal<Theme[]>([]);
  protected readonly selectedId = signal('');
  protected readonly version = signal(0); // bumped on save -> busts the frames

  // Editable copies of the selected theme and the global branding.
  protected readonly name = signal('');
  protected readonly flat = signal(false);
  protected readonly dark = signal<Record<string, string>>({});
  protected readonly light = signal<Record<string, string>>({});
  protected readonly brandName = signal('');
  protected readonly brandTagline = signal('');
  protected readonly brandLogo = signal('');
  protected readonly brandFavicon = signal('');
  // The flow pages' look. It rides on /api/settings, whose PUT takes the WHOLE
  // payload, so the loaded object is kept to send back with one field changed -
  // a partial body would quietly reset the rest.
  protected readonly pagesScheme = signal<'' | 'light' | 'dark'>('');
  private settings: Settings | null = null;

  // Hovered token (from the palette editor) -> CSS var for the preview.
  private readonly hoverKey = signal('');
  protected readonly highlightVar = computed(() => (this.hoverKey() ? CSS_VARS[this.hoverKey()] : ''));

  protected readonly selected = computed(
    () => this.themes().find((t) => t.id === this.selectedId()) ?? null,
  );

  constructor() {
    this.load();
    this.api.listPresets().subscribe({ next: (p) => this.presets.set(p) });
    this.api.settings().subscribe({
      next: (s) => {
        this.settings = s;
        this.pagesScheme.set(s.pagesScheme ?? '');
      },
      error: () => undefined,
    });
    this.api.branding().subscribe({
      next: (b) => {
        this.brandName.set(b.appName);
        this.brandTagline.set(b.tagline);
        this.brandLogo.set(b.logo);
        this.brandFavicon.set(b.favicon ?? '');
      },
    });
  }

  protected hover(key: string): void {
    this.hoverKey.set(key);
  }

  protected select(t: Theme): void {
    this.selectedId.set(t.id);
    this.name.set(t.name);
    this.flat.set(!!t.flat);
    this.dark.set({ ...t.dark });
    this.light.set({ ...t.light });
  }

  private load(keepSelection = false): void {
    this.loading.set(true);
    this.api.listThemes().subscribe({
      next: (themes) => {
        this.themes.set(themes);
        const wanted = keepSelection ? this.selectedId() : '';
        const pick = themes.find((t) => t.id === wanted) ?? themes.find((t) => t.active) ?? themes[0];
        if (pick) this.select(pick);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  // "+" menu: start a new theme from a built-in palette (auto-named after it).
  protected createFromPreset(p: Theme): void {
    this.create(this.uniqueName(p.name), { ...p.dark }, { ...p.light }, p.flat);
  }

  // "Duplicate": derive a new theme from the selected one, auto-named. It
  // inherits the source's createdAt so it sorts right NEXT TO it (in place),
  // not at the end (ListThemes orders by createdAt then name; "X copy" > "X").
  protected createFrom(): void {
    const base = this.selected();
    if (!base) return;
    this.create(
      this.uniqueName(`${base.name} copy`),
      { ...this.dark() },
      { ...this.light() },
      this.flat(),
      base.createdAt,
    );
  }

  private uniqueName(base: string): string {
    const taken = new Set(this.themes().map((t) => t.name));
    if (!taken.has(base)) return base;
    for (let i = 2; ; i++) {
      const candidate = `${base} ${i}`;
      if (!taken.has(candidate)) return candidate;
    }
  }

  private create(
    name: string,
    dark: Record<string, string>,
    light: Record<string, string>,
    flat = false,
    createdAt?: number,
  ): void {
    this.api.createTheme({ name, dark, light, flat, ...(createdAt ? { createdAt } : {}) }).subscribe({
      next: (created) => {
        this.selectedId.set(created.id);
        this.load(true);
      },
      error: (err) => this.snack.open(errMsg(err), undefined, { duration: 4000 }),
    });
  }

  // Branding is global - its persistence is deliberately separate from themes.
  protected onPagesScheme(value: '' | 'light' | 'dark'): void {
    this.pagesScheme.set(value);
    this.savePagesScheme(value);
  }

  // Saved as soon as a box is ticked: the two checkboxes ARE the setting, so
  // asking for a Save button beside them would be asking twice.
  private savePagesScheme(value: '' | 'light' | 'dark'): void {
    const current = this.settings;
    if (!current) return;
    this.api.saveSettings({ ...current, pagesScheme: value }).subscribe({
      next: (s) => {
        this.settings = s;
        this.snack.open($localize`:@@Saved:Saved`, undefined, { duration: 2000 });
      },
      error: (err) => this.snack.open(errMsg(err), undefined, { duration: 4000 }),
    });
  }

  protected saveBranding(): void {
    this.api
      .saveBranding({
        appName: this.brandName().trim(),
        tagline: this.brandTagline().trim(),
        logo: this.brandLogo(),
        favicon: this.brandFavicon(),
      })
      .subscribe({
        next: () => this.snack.open($localize`:@@Branding_saved:Branding saved`, undefined, { duration: 2500 }),
        error: (err) => this.snack.open(errMsg(err), undefined, { duration: 4000 }),
      });
  }

  protected save(): void {
    const t = this.selected();
    if (!t) return;
    this.saving.set(true);
    this.api
      .updateTheme({ ...t, name: this.name().trim(), flat: this.flat(), dark: this.dark(), light: this.light() })
      .subscribe({
        next: () => {
          this.saving.set(false);
          this.version.update((v) => v + 1);
          this.load(true);
        },
        error: (err) => {
          this.saving.set(false);
          this.snack.open(errMsg(err), undefined, { duration: 4000 });
        },
      });
  }

  protected activate(t: Theme): void {
    this.api.activateTheme(t.id).subscribe({
      next: () => {
        this.snack.open(
          $localize`:@@Theme_is_now_live:This theme is now live on the flow pages`,
          undefined,
          { duration: 3000 },
        );
        this.load(true);
      },
      error: (err) => this.snack.open(errMsg(err), undefined, { duration: 4000 }),
    });
  }

  protected async remove(t: Theme): Promise<void> {
    const ok = await this.dialogs.confirm({
      title: $localize`:@@Delete_this_theme:Delete this theme?`,
      confirmLabel: $localize`:@@Delete:Delete`,
      danger: true,
    });
    if (!ok) return;
    this.api.deleteTheme(t.id).subscribe({
      next: () => this.load(),
      error: (err) => this.snack.open(errMsg(err), undefined, { duration: 4000 }),
    });
  }
}

function errMsg(err: unknown): string {
  const e = err as { error?: { error?: string } };
  return typeof e?.error?.error === 'string' ? e.error.error : $localize`:@@Request_failed:Request failed`;
}
