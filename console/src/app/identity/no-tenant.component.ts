import { Component } from '@angular/core';

// Where /tenants lands when there is no tenant to forward to.
@Component({
  selector: 'app-no-tenant',
  styles: [
    `
      :host {
        display: flex;
        align-items: center;
        justify-content: center;
        height: 100%;
        color: var(--mat-sys-on-surface-variant);
      }
    `,
  ],
  template: `<p i18n="@@No_tenant_yet">No tenant yet</p>`,
})
export class NoTenantComponent {}
