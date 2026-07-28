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
  styleUrl: './vault-page.component.scss',
  templateUrl: './vault-page.component.html',
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
