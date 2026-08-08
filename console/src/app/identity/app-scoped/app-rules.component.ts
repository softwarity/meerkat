import { Component, inject } from '@angular/core';
import { ApiService } from '../../api.service';
import { MeService } from '../../me.service';
import { TenantRulesComponent } from '../tenant-sections/tenant-rules.component';
import { TenantScope } from '../tenant-scope';

// Group rules, seen from Application.
//
// They project what a DIRECTORY declares onto groups here, so they are part of
// the directories feature and carry its lock. They have to be reachable in
// single-tenant mode: someone running one organisation with an LDAP is exactly
// who needs them, and leaving them under /tenants would have hidden them from
// the only people they are for.
//
// The screen underneath is untouched - it reads the organisation from
// TenantScope, which this wrapper provides with the served one instead of the
// one in the URL.
@Component({
  selector: 'app-app-rules',
  imports: [TenantRulesComponent],
  providers: [TenantScope],
  template: `
    <div class="banner">
      <h1 i18n="@@Group_rules">Group rules</h1>
    </div>
    <div class="panel">
      <app-tenant-rules ee-feature="directories" />
    </div>
  `,
  styles: [
    `
      :host {
        display: flex;
        flex-direction: column;
        height: 100%;
        min-height: 0;
      }
      .banner {
        display: flex;
        align-items: center;
        gap: 16px;
        padding: 12px 24px;
        flex: none;
      }
      .banner h1 {
        font-size: 1.15rem;
        font-weight: 500;
        margin: 0;
        flex: 1;
      }
      /* The same frame the organisation page gives its sections: without it
         the matrix touched the window edges here and nowhere else. */
      .panel {
        flex: 1 1 auto;
        min-height: 0;
        min-width: 0;
        display: flex;
        flex-direction: column;
        overflow: hidden;
        padding: 0 24px 20px;
      }
      .panel > * {
        flex: 1 1 auto;
        min-height: 0;
      }
    `,
  ],
})
export class AppRulesComponent {
  private readonly api = inject(ApiService);
  private readonly me = inject(MeService);
  private readonly scope = inject(TenantScope);

  constructor() {
    const id = this.me.primaryTenant();
    if (id) {
      this.api.getTenant(id).subscribe({ next: (t) => this.scope.tenant.set(t), error: () => undefined });
    }
  }
}
