import { Component, LOCALE_ID, inject } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';
import { MatMenuModule } from '@angular/material/menu';
import { RailnavItemComponent } from '@softwarity/rail-nav';

// The console is served per locale under /<lg>/ (Angular i18n builds, fronted
// by polyglot in dev). Switching language = navigating to the same route in
// the other locale's build. Language names are native, never translated.
const LOCALES: readonly { code: string; label: string }[] = [
  { code: 'en', label: 'English' },
  { code: 'fr', label: 'Français' },
];

@Component({
  selector: 'app-lang-select',
  imports: [MatIconModule, MatMenuModule, RailnavItemComponent],
  template: `
    <rail-nav-item [label]="current.label" [matMenuTriggerFor]="langMenu">
      <mat-icon>language</mat-icon>
    </rail-nav-item>
    <mat-menu #langMenu="matMenu">
      @for (locale of locales; track locale.code) {
        <button mat-menu-item [disabled]="locale.code === current.code" (click)="use(locale.code)">
          {{ locale.label }}
        </button>
      }
    </mat-menu>
  `,
})
export class LangSelectComponent {
  private readonly localeId = inject(LOCALE_ID);
  protected readonly locales = LOCALES;
  protected readonly current =
    LOCALES.find((l) => this.localeId.startsWith(l.code)) ?? LOCALES[0];

  protected use(code: string): void {
    const path = location.pathname;
    const swapped = /^\/(en|fr)(\/|$)/.test(path)
      ? path.replace(/^\/(en|fr)/, `/${code}`)
      : `/${code}${path}`;
    location.href = swapped + location.search;
  }
}
