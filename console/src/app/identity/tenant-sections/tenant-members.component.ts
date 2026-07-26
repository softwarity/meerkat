import { Component, inject } from '@angular/core';
import { MembersMatrixComponent } from '../members-matrix/members-matrix.component';
import { TenantScope } from '../tenant-scope';

// Thin routed wrapper: the members matrix, fed by the layout's scope (tenant +
// header search).
@Component({
  selector: 'app-tenant-members',
  imports: [MembersMatrixComponent],
  styles: [
    `
      :host {
        display: flex;
        flex-direction: column;
        height: 100%;
        min-height: 0;
      }
      app-members-matrix {
        flex: 1 1 auto;
        min-height: 0;
      }
    `,
  ],
  template: `
    @if (scope.tenant(); as t) {
      <app-members-matrix [tenantId]="t.id" [ownerId]="t.ownerId" [filter]="scope.filter()" />
    }
  `,
})
export class TenantMembersComponent {
  protected readonly scope = inject(TenantScope);
}
