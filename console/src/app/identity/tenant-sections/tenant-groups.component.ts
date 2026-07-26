import { Component, inject } from '@angular/core';
import { GroupsMatrixComponent } from '../groups-matrix/groups-matrix.component';
import { TenantScope } from '../tenant-scope';

// Thin routed wrapper: the groups matrix, fed by the layout's scope (tenant +
// header search).
@Component({
  selector: 'app-tenant-groups',
  imports: [GroupsMatrixComponent],
  styles: [
    `
      :host {
        display: flex;
        flex-direction: column;
        height: 100%;
        min-height: 0;
      }
      app-groups-matrix {
        flex: 1 1 auto;
        min-height: 0;
      }
    `,
  ],
  template: `
    @if (scope.tenant(); as t) {
      <app-groups-matrix
        [tenantId]="t.id"
        [filter]="scope.filter()"
        [tagFilter]="scope.tagFilter()"
        (availableTags)="scope.tags.set($event)"
      />
    }
  `,
})
export class TenantGroupsComponent {
  protected readonly scope = inject(TenantScope);
}
