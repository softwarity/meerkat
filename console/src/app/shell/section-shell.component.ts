import { Component, inject } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';
import { ActivatedRoute, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';

// One section entry in a plane's left nav. The path is RELATIVE to the plane,
// so /infra/routes and /application/users need no repetition here.
interface SectionLink {
  path: string;
  label: string;
  icon: string;
  roles?: string;
}

const PLANES: Record<string, { title: string; links: SectionLink[] }> = {
  infra: {
    title: $localize`:@@Infra:Infra`,
    links: [
      { path: 'routes', label: $localize`:@@Routes:Routes`, icon: 'alt_route' },
      {
        path: 'endpoint-security',
        label: $localize`:@@Endpoint_security:Endpoint security`,
        icon: 'security',
      },
      { path: 'mail-relay', label: $localize`:@@Mail_relay:Mail relay`, icon: 'outgoing_mail' },
      {
        path: 'access-tokens',
        label: $localize`:@@Access_tokens:Access tokens`,
        icon: 'key',
        roles: 'root',
      },
    ],
  },
  application: {
    title: $localize`:@@Application:Application`,
    links: [
      { path: 'general', label: $localize`:@@Section_general:General`, icon: 'tune' },
      { path: 'locales', label: $localize`:@@Locales:Locales`, icon: 'translate' },
      { path: 'roles', label: $localize`:@@Roles:Roles`, icon: 'badge' },
      { path: 'users', label: $localize`:@@Users:Users`, icon: 'group' },
      { path: 'built-in-pages', label: $localize`:@@Built_in_pages:Built-in pages`, icon: 'web' },
      { path: 'security', label: $localize`:@@Security:Security`, icon: 'shield' },
    ],
  },
};

// The console shell: a plane's sections live in a LEFT NAV inside the page, the
// same shape a tenant already had, rather than in a drawer sliding out of the
// rail. Sections are CHILD routes (/infra/routes, /application/users), so the
// URL says which plane one is in and this shell stays mounted while moving
// between sections. Which plane it serves comes from the route's `plane` data —
// the router already knows, so there is no URL to parse.
//
// The transverse screens (vault, audit) sit outside: they belong to no plane.
// So does a tenant, which brings its own nav.
@Component({
  selector: 'app-section-shell',
  imports: [MatIconModule, RouterLink, RouterLinkActive, RouterOutlet],
  styles: [
    `
      :host {
        display: flex;
        height: 100%;
        width: 100%;
        min-height: 0;
        /* The two zones own their scrolling; nothing escapes to the page. */
        overflow: hidden;
      }
      nav.left {
        flex: 0 0 200px;
        display: flex;
        flex-direction: column;
        gap: 2px;
        border-right: 1px solid var(--mat-sys-outline-variant);
        padding: 0 8px;
        overflow-y: auto;
      }
      nav.left h2 {
        margin: 0 -8px 6px;
        padding: 16px 16px 12px;
        font-size: 1.1rem;
        font-weight: 500;
        border-bottom: 1px solid var(--mat-sys-outline-variant);
      }
      .section-link {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 10px 14px;
        border-radius: 999px;
        color: var(--mat-sys-on-surface);
        text-decoration: none;
        white-space: nowrap;
      }
      .section-link:hover {
        background: var(--mat-sys-surface-container-high);
      }
      .section-link.active {
        background: var(--mat-sys-secondary-container);
        color: var(--mat-sys-on-secondary-container);
      }
      /* The working zone scrolls on its own: the section nav stays put however
         long the content is. A section that manages its own scrolling (a table
         with a sticky header) simply never overflows this one. */
      .right {
        flex: 1;
        min-width: 0;
        min-height: 0;
        display: flex;
        flex-direction: column;
        overflow-y: auto;
      }
      .right > * {
        min-height: 0;
      }
    `,
  ],
  template: `
    @if (sections.length) {
      <nav class="left">
        <h2>{{ title }}</h2>
        @for (s of sections; track s.path) {
          <a
            [routerLink]="s.path"
            routerLinkActive="active"
            class="section-link"
            [attr.any-role]="s.roles || null"
          >
            <mat-icon>{{ s.icon }}</mat-icon>
            <span>{{ s.label }}</span>
          </a>
        }
      </nav>
    }
    <div class="right">
      <router-outlet />
    </div>
  `,
})
export class SectionShellComponent {
  private readonly plane = (inject(ActivatedRoute).snapshot.data['plane'] as string) ?? '';

  protected readonly sections: SectionLink[] = PLANES[this.plane]?.links ?? [];
  protected readonly title = PLANES[this.plane]?.title ?? '';
}
