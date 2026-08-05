import { Component, computed, effect, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatSnackBar } from '@angular/material/snack-bar';
import { Router } from '@angular/router';
import { catchError, of } from 'rxjs';
import { ApiService, Member } from '../../api.service';
import { DialogsService } from '../../shared/dialogs.service';
import { TenantScope } from '../tenant-scope';
import { TenantsService } from '../../shared/tenants.service';

// The tenant's Danger zone (a child route of the tenant layout), GitHub-style:
// outlined error cards for the destructive acts: ownership transfer (reassigns
// Tenant.ownerId, decoupled from membership) and type-to-confirm deletion.
@Component({
  selector: 'app-tenant-danger',
  imports: [MatButtonModule, MatCardModule, MatFormFieldModule, MatSelectModule],
  styles: [
    `
      :host {
        display: block;
      }
      .danger-cards {
        display: grid;
        gap: 16px;
        max-width: 640px;
      }
      .danger-card {
        padding: 16px 20px;
        border-color: color-mix(in srgb, var(--mat-sys-error) 55%, transparent);
      }
      .danger-card h3 {
        margin: 0 0 6px;
        font-size: 0.95rem;
        font-weight: 500;
      }
      .danger-card .hint {
        margin: 0 0 12px;
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.85rem;
      }
      .danger-row {
        display: flex;
        align-items: center;
        gap: 12px;
        flex-wrap: wrap;
      }
      .owner-pick {
        flex: 1 1 220px;
        max-width: 320px;
      }
      .danger-btn {
        --mdc-outlined-button-label-text-color: var(--mat-sys-error);
        --mdc-outlined-button-outline-color: color-mix(in srgb, var(--mat-sys-error) 55%, transparent);
      }
    `,
  ],
  template: `
    <div class="danger-cards">
      <mat-card appearance="outlined" class="danger-card">
        <h3 i18n="@@Transfer_ownership">Transfer ownership</h3>
        <p class="hint" i18n="@@Transfer_ownership_hint">
          A tenant has a single owner. The chosen member becomes it. Ownership is independent of
          membership, so the previous owner keeps their membership unchanged.
        </p>
        @if (currentOwnerName(); as owner) {
          <p class="hint">
            <ng-container i18n="@@Current_owner">Current owner</ng-container>:
            <strong>{{ owner }}</strong>
          </p>
        }
        <div class="danger-row">
          <mat-form-field class="owner-pick" subscriptSizing="dynamic">
            <mat-label i18n="@@New_owner">New owner</mat-label>
            <mat-select [value]="transferTo()" (selectionChange)="transferTo.set($event.value)">
              @for (m of transferCandidates(); track m.userId) {
                <mat-option [value]="m.userId">{{ m.username }}</mat-option>
              }
            </mat-select>
          </mat-form-field>
          <button
            matButton="outlined"
            class="danger-btn"
            [disabled]="!transferTo()"
            (click)="transferOwnership()"
            i18n="@@Transfer"
          >
            Transfer
          </button>
        </div>
      </mat-card>

      <mat-card appearance="outlined" class="danger-card">
        <h3 i18n="@@Delete_this_tenant">Delete this tenant</h3>
        <p class="hint" i18n="@@Delete_this_tenant_hint">
          Removes the tenant, its memberships and its groups. There is no undo.
        </p>
        <div class="danger-row">
          <button matButton="outlined" class="danger-btn" (click)="removeTenant()" i18n="@@Delete_tenant">
            Delete tenant
          </button>
        </div>
      </mat-card>
    </div>
  `,
})
export class TenantDangerComponent {
  private readonly api = inject(ApiService);
  private readonly tenants = inject(TenantsService);
  private readonly snack = inject(MatSnackBar);
  private readonly dialogs = inject(DialogsService);
  private readonly router = inject(Router);
  protected readonly scope = inject(TenantScope);

  protected readonly members = signal<Member[]>([]);
  protected readonly transferTo = signal('');
  // Ownership lives on the tenant now (ownerId), not the membership list.
  protected readonly currentOwnerName = computed(() => this.scope.tenant()?.ownerName ?? '');
  protected readonly transferCandidates = computed(() => {
    const ownerId = this.scope.tenant()?.ownerId;
    return this.members().filter((m) => m.userId !== ownerId);
  });

  constructor() {
    effect(() => {
      const t = this.scope.tenant();
      if (t) this.loadMembers(t.id);
    });
  }

  private loadMembers(tenantId: string): void {
    this.api
      .listMembers(tenantId)
      .pipe(catchError(() => of<Member[]>([])))
      .subscribe((members) => {
        this.members.set(members);
        this.transferTo.set('');
      });
  }

  // Ownership is a tenant field (TENANT-02): the transfer reassigns ownerId and
  // leaves every membership untouched.
  protected async transferOwnership(): Promise<void> {
    const t = this.scope.tenant();
    const grantee = this.members().find((m) => m.userId === this.transferTo());
    if (!t || !grantee) return;
    const ok = await this.dialogs.confirm({
      title: $localize`:@@Transfer_ownership_to_USERNAME:Transfer ownership to "${grantee.username}:USERNAME:"?`,
      confirmLabel: $localize`:@@Transfer:Transfer`,
      danger: true,
    });
    if (!ok) return;
    this.api.transferOwner(t.id, grantee.userId).subscribe({
      next: (saved) => {
        this.snack.open(
          $localize`:@@USERNAME_is_now_the_owner:"${grantee.username}:USERNAME:" is now the owner`,
          undefined,
          { duration: 2500 },
        );
        // Push the fresh tenant back so the owner name updates everywhere.
        this.scope.tenant.set(saved);
        this.transferTo.set('');
      },
      error: (err) => this.snack.open(errMsg(err), undefined, { duration: 4000 }),
    });
  }

  protected async removeTenant(): Promise<void> {
    const t = this.scope.tenant();
    if (!t) return;
    // Type-to-confirm: destroying a tenant wipes its members and settings.
    const typed = await this.dialogs.prompt({
      title: $localize`:@@Delete_tenant_NAME:Delete tenant "${t.name}:NAME:"?`,
      label: $localize`:@@Type_the_tenant_name_to_confirm:Type the tenant name to confirm`,
      confirmLabel: $localize`:@@Delete:Delete`,
      requireMatch: t.name,
      danger: true,
    });
    if (typed !== t.name) return;
    this.api.deleteTenant(t.id).subscribe({
      next: () => {
        // The rail's drawer holds its own list: without this it keeps offering
        // a link to an organisation that no longer exists.
        this.tenants.remove(t.id);
        void this.router.navigate(['/']);
      },
      error: (err) => this.snack.open(errMsg(err), undefined, { duration: 4000 }),
    });
  }
}

function errMsg(err: unknown): string {
  const e = err as { error?: { error?: string } };
  return typeof e?.error?.error === 'string' ? e.error.error : $localize`:@@Request_failed:Request failed`;
}
