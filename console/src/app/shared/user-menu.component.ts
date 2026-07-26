import { Component, LOCALE_ID, computed, inject } from '@angular/core';
import { MatDividerModule } from '@angular/material/divider';
import { MatIconModule } from '@angular/material/icon';
import { MatMenuModule } from '@angular/material/menu';
import { RailnavItemComponent } from '@softwarity/rail-nav';
import { ApiService } from '../api.service';
import { MeService } from '../me.service';

// The console is served per locale under /<lg>/ (Angular i18n builds, fronted
// by polyglot in dev). Switching language = navigating to the same route in
// the other locale's build. Language names are native, never translated.
const LOCALES: readonly { code: string; label: string }[] = [
  { code: 'en', label: 'English' },
  { code: 'fr', label: 'Français' },
];

// The rail's bottom entry: one user menu instead of separate language and
// sign-out items — who you are (from the identity the gateway stamps on
// <body>), the console language as a submenu, and sign out.
@Component({
  selector: 'app-user-menu',
  imports: [MatDividerModule, MatIconModule, MatMenuModule, RailnavItemComponent],
  styles: [
    `
      .avatar {
        display: grid;
        place-items: center;
        width: 26px;
        height: 26px;
        border-radius: 50%;
        background: var(--mat-sys-primary);
        color: var(--mat-sys-on-primary);
        font-size: 0.7rem;
        font-weight: 700;
        letter-spacing: 0.02em;
      }
      .who {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 12px 16px;
        cursor: default;
      }
      .who .avatar {
        width: 36px;
        height: 36px;
        font-size: 0.85rem;
      }
      .who .lines {
        display: grid;
        line-height: 1.3;
      }
      .who .name {
        font-weight: 600;
      }
      .who .email {
        font-size: 0.78rem;
        color: var(--mat-sys-on-surface-variant);
      }
    `,
  ],
  template: `
    <rail-nav-item [label]="username()" [matMenuTriggerFor]="userMenu">
      @if (initials()) {
        <span class="avatar">{{ initials() }}</span>
      } @else {
        <mat-icon>person</mat-icon>
      }
    </rail-nav-item>
    <mat-menu #userMenu="matMenu">
      @if (user(); as u) {
        <div class="who" (click)="$event.stopPropagation()">
          <span class="avatar">{{ initials() }}</span>
          <span class="lines">
            <span class="name">{{ u.fullname || u.username }}</span>
            @if (u.email) {
              <span class="email">{{ u.email }}</span>
            }
          </span>
        </div>
        <mat-divider />
      }
      <button mat-menu-item [matMenuTriggerFor]="langMenu">
        <mat-icon>language</mat-icon>
        <span>{{ current.label }}</span>
      </button>
      <mat-divider />
      <button mat-menu-item (click)="logout()">
        <mat-icon>logout</mat-icon>
        <span i18n="@@Sign_out">Sign out</span>
      </button>
    </mat-menu>
    <mat-menu #langMenu="matMenu">
      @for (locale of locales; track locale.code) {
        <button mat-menu-item [disabled]="locale.code === current.code" (click)="use(locale.code)">
          {{ locale.label }}
        </button>
      }
    </mat-menu>
  `,
})
export class UserMenuComponent {
  private readonly api = inject(ApiService);
  private readonly localeId = inject(LOCALE_ID);

  protected readonly user = inject(MeService).user;
  protected readonly username = computed(() => this.user()?.username ?? '');
  protected readonly initials = computed(() => {
    const u = this.user();
    if (!u) return '';
    const parts = (u.fullname || u.username).trim().split(/\s+/);
    return ((parts[0]?.[0] ?? '') + (parts[1]?.[0] ?? parts[0]?.[1] ?? '')).toUpperCase();
  });

  protected readonly locales = LOCALES;
  protected readonly current = LOCALES.find((l) => this.localeId.startsWith(l.code)) ?? LOCALES[0];

  protected use(code: string): void {
    const path = location.pathname;
    const swapped = /^\/(en|fr)(\/|$)/.test(path)
      ? path.replace(/^\/(en|fr)/, `/${code}`)
      : `/${code}${path}`;
    location.href = swapped + location.search;
  }

  protected logout(): void {
    this.api.logout().subscribe({
      next: () => (location.href = '/login'),
      error: () => (location.href = '/login'),
    });
  }
}
