import { Component, computed, inject, signal } from '@angular/core';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { ApiService, Tenant } from '../../api.service';
import { MeService } from '../../me.service';
import { MembersMatrixComponent } from '../members-matrix/members-matrix.component';

// Who is in which group, seen from Application.
//
// Users and this screen answer two different questions and stay apart: Users
// is the account - who exists, what they may do across the whole gateway -
// while this is the assignment. In single-tenant mode the matrix loses the two
// columns that stop meaning anything: belonging (an enabled account IS a
// member here) and the ADMIN badge (the app-admin capability already says it).
// Both are marked multi-tenant-only inside the matrix itself.
@Component({
  selector: 'app-app-members',
  imports: [MatFormFieldModule, MatInputModule, MembersMatrixComponent],
  template: `
    <div class="banner">
      <h1 i18n="@@Members">Members</h1>
    </div>

    <div class="toolbar">
      <mat-form-field class="search" subscriptSizing="dynamic">
        <mat-label i18n="@@Search">Search</mat-label>
        <input matInput [value]="filter()" (input)="filter.set($any($event.target).value)" />
      </mat-form-field>
    </div>

    @if (tenantId(); as id) {
      <div class="panel">
        <app-members-matrix [tenantId]="id" [ownerId]="ownerId()" [filter]="filter()" />
      </div>
    }
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
      .toolbar {
        flex: none;
        padding: 0 24px 12px;
      }
      .search {
        width: 100%;
        max-width: 420px;
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
export class AppMembersComponent {
  private readonly api = inject(ApiService);
  private readonly me = inject(MeService);

  protected readonly filter = signal('');
  private readonly tenant = signal<Tenant | null>(null);

  protected readonly tenantId = computed(() => this.tenant()?.id ?? this.me.primaryTenant());
  protected readonly ownerId = computed(() => this.tenant()?.ownerId ?? '');

  constructor() {
    const id = this.me.primaryTenant();
    if (id) {
      this.api.getTenant(id).subscribe({ next: (t) => this.tenant.set(t), error: () => undefined });
    }
  }
}
