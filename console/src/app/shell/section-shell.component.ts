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
      {
        path: 'auth-providers',
        label: $localize`:@@Authentication:Authentication`,
        icon: 'passkey',
      },
      { path: 'mail-relay', label: $localize`:@@Mail_relay:Mail relay`, icon: 'outgoing_mail' },
      {
        path: 'access-tokens',
        label: $localize`:@@Access_tokens:Access tokens`,
        icon: 'key',
        roles: 'root',
      },
      { path: 'others', label: $localize`:@@Others:Others`, icon: 'more_horiz' },
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
  styleUrl: './section-shell.component.scss',
  templateUrl: './section-shell.component.html',
})
export class SectionShellComponent {
  private readonly plane = (inject(ActivatedRoute).snapshot.data['plane'] as string) ?? '';

  protected readonly sections: SectionLink[] = PLANES[this.plane]?.links ?? [];
  protected readonly title = PLANES[this.plane]?.title ?? '';
}
