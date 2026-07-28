import { Component, computed, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatDialog } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { MatTooltipModule } from '@angular/material/tooltip';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import { RowActionsDirective } from '@softwarity/row-actions';
import { ApiService, VaultEntry } from '../api.service';
import { DialogsService } from '../shared/dialogs.service';
import { VaultEntryDialogComponent, VaultEntryDialogData } from '../shared/vault-entry-dialog.component';
import { VaultService } from '../shared/vault.service';

// The vault (VAULT-01/02): every named value the configuration refers to, in
// one place. Secrets are encrypted at rest and never shown again; plain values
// are readable. Both are referenced the same way, by $name, so promoting a
// value to a secret never touches what points at it. The "used by" column is
// what tells a live entry from a leftover.
@Component({
  selector: 'app-vault-page',
  imports: [
    MatButtonModule,
    MatIconModule,
    MatTableModule,
    MatTooltipModule,
    LoadingIndicatorComponent,
    RowActionsDirective,
  ],
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
        gap: 12px;
        padding: 12px 24px;
        flex: none;
      }
      .banner h1 {
        font-size: 1.15rem;
        font-weight: 500;
        margin: 0;
      }
      .hint {
        flex: 1;
        margin: 0;
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.82rem;
        max-width: 70ch;
      }
      .content {
        flex: 1 1 auto;
        min-height: 0;
        overflow-y: auto;
        padding: 0 24px 88px;
      }
      .empty {
        padding: 48px;
        text-align: center;
        color: var(--mat-sys-on-surface-variant);
      }
      .clickable {
        cursor: pointer;
      }
      .clickable:hover {
        background: var(--mat-sys-surface-container-high);
      }
      .name {
        font-family: var(--mk-mono);
        font-weight: 500;
      }
      .desc {
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.82rem;
      }
      .val {
        font-family: var(--mk-mono);
        font-size: 0.82rem;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .hidden-val {
        color: var(--mat-sys-on-surface-variant);
        font-style: italic;
        font-size: 0.82rem;
      }
      .kind {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        padding: 1px 10px;
        border-radius: 999px;
        font-size: 0.7rem;
        letter-spacing: 0.04em;
        background: var(--mat-sys-surface-container-high);
        color: var(--mat-sys-on-surface-variant);
      }
      .kind.secret {
        background: color-mix(in srgb, var(--mk-signal) 22%, transparent);
        color: var(--mat-sys-on-surface);
      }
      .kind mat-icon {
        font-size: 14px;
        width: 14px;
        height: 14px;
      }
      .used {
        display: flex;
        flex-wrap: wrap;
        gap: 4px;
      }
      .use {
        font-size: 0.7rem;
        padding: 1px 8px;
        border-radius: 999px;
        background: var(--mat-sys-surface-container-high);
        color: var(--mat-sys-on-surface-variant);
      }
      .unused {
        color: var(--mat-sys-outline);
        font-size: 0.75rem;
        font-style: italic;
      }
      .c-kind {
        flex: 0 0 130px;
      }
      .fab-new {
        position: absolute;
        right: 24px;
        bottom: 24px;
      }
    `,
  ],
  template: `
    <div class="banner">
      <h1 i18n="@@Vault">Vault</h1>
      <p class="hint" i18n="@@Vault_hint">
        Every value the configuration refers to, in one place. Use one anywhere with $name: secrets
        are encrypted and never shown again, plain values stay readable.
      </p>
    </div>

    <div class="content">
      @if (loading()) {
        <loading-indicator withContainer />
      } @else if (entries().length === 0) {
        <div class="empty" i18n="@@No_vault_entry">No entry yet. Add the first one.</div>
      } @else {
        <mat-table [dataSource]="entries()">
          <ng-container matColumnDef="name">
            <mat-header-cell *matHeaderCellDef i18n="@@Name">Name</mat-header-cell>
            <mat-cell *matCellDef="let e">
              <span>
                <span class="name">{{ e.name }}</span>
                @if (e.description) {
                  <div class="desc">{{ e.description }}</div>
                }
              </span>
            </mat-cell>
          </ng-container>

          <ng-container matColumnDef="kind">
            <mat-header-cell *matHeaderCellDef class="c-kind" i18n="@@Kind">Kind</mat-header-cell>
            <mat-cell *matCellDef="let e" class="c-kind">
              <span class="kind" [class.secret]="e.kind === 'secret'">
                <mat-icon>{{ e.kind === 'secret' ? 'lock' : 'label' }}</mat-icon>
                @if (e.kind === 'secret') {
                  <ng-container i18n="@@Kind_secret">Secret</ng-container>
                } @else {
                  <ng-container i18n="@@Kind_value">Value</ng-container>
                }
              </span>
            </mat-cell>
          </ng-container>

          <ng-container matColumnDef="value">
            <mat-header-cell *matHeaderCellDef i18n="@@Value">Value</mat-header-cell>
            <mat-cell *matCellDef="let e">
              @if (e.kind === 'secret') {
                <span class="hidden-val" i18n="@@Secret_hidden">encrypted, never shown</span>
              } @else {
                <span class="val">{{ e.value }}</span>
              }
            </mat-cell>
          </ng-container>

          <ng-container matColumnDef="usedBy">
            <mat-header-cell *matHeaderCellDef i18n="@@Used_by">Used by</mat-header-cell>
            <mat-cell *matCellDef="let e">
              @if (e.usedBy?.length) {
                <span class="used">
                  @for (u of e.usedBy; track u) {
                    <span class="use">{{ u }}</span>
                  }
                </span>
              } @else {
                <span class="unused" i18n="@@Not_used">not used</span>
              }
              <span rowActions="tonal">
                <button
                  matIconButton
                  (click)="$event.stopPropagation(); remove(e)"
                  i18n-matTooltip="@@Delete"
                  matTooltip="Delete"
                  i18n-aria-label="@@Delete"
                  aria-label="Delete"
                >
                  <mat-icon>delete</mat-icon>
                </button>
              </span>
            </mat-cell>
          </ng-container>

          <mat-header-row *matHeaderRowDef="columns; sticky: true"></mat-header-row>
          <mat-row *matRowDef="let row; columns: columns" class="clickable" (click)="edit(row)"></mat-row>
        </mat-table>
      }
    </div>

    <button
      matFab
      class="fab-new"
      (click)="create()"
      i18n-matTooltip="@@New_vault_entry"
      matTooltip="New entry"
      i18n-aria-label="@@New_vault_entry"
      aria-label="New entry"
    >
      <mat-icon>add</mat-icon>
    </button>
  `,
})
export class VaultPageComponent {
  private readonly api = inject(ApiService);
  private readonly vault = inject(VaultService);
  private readonly dialog = inject(MatDialog);
  private readonly dialogs = inject(DialogsService);
  private readonly snack = inject(MatSnackBar);

  protected readonly loading = signal(true);
  protected readonly entries = computed(() => this.vault.entries());
  protected readonly columns = ['name', 'kind', 'value', 'usedBy'];

  constructor() {
    void this.vault.reload().then(() => this.loading.set(false));
  }

  protected create(): void {
    this.dialog.open<VaultEntryDialogComponent, VaultEntryDialogData>(VaultEntryDialogComponent, {
      data: {},
      restoreFocus: true,
      disableClose: true,
    });
  }

  protected edit(entry: VaultEntry): void {
    this.dialog.open<VaultEntryDialogComponent, VaultEntryDialogData>(VaultEntryDialogComponent, {
      data: { entry },
      restoreFocus: true,
      disableClose: true,
    });
  }

  protected async remove(entry: VaultEntry): Promise<void> {
    const ok = await this.dialogs.confirm({
      title: $localize`:@@Delete_vault_entry_NAME:Delete "${entry.name}:NAME:"?`,
      confirmLabel: $localize`:@@Delete:Delete`,
      danger: true,
    });
    if (!ok) return;
    this.api.deleteVaultEntry(entry.scope, entry.name).subscribe({
      next: () => void this.vault.reload(),
      error: (err: unknown) => {
        const e = err as { error?: { error?: string } };
        this.snack.open(
          typeof e?.error?.error === 'string' ? e.error.error : $localize`:@@Request_failed:Request failed`,
          undefined,
          { duration: 5000 },
        );
      },
    });
  }
}
