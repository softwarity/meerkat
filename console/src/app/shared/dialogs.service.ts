import { Service, inject } from '@angular/core';
import { MatDialog } from '@angular/material/dialog';
import { firstValueFrom } from 'rxjs';
import { ConfirmData, ConfirmDialogComponent } from './confirm-dialog.component';
import { PromptData, PromptDialogComponent } from './prompt-dialog.component';

// Themed replacements for the browser's native confirm()/prompt(), whose look
// is imposed by the OS and clashes with the console everywhere it appears. One
// place to open them so call sites stay a single awaited line.
@Service()
export class DialogsService {
  private readonly dialog = inject(MatDialog);

  // Resolves true only when the user confirms.
  confirm(data: ConfirmData): Promise<boolean> {
    return firstValueFrom(
      this.dialog.open(ConfirmDialogComponent, { data, width: '440px', restoreFocus: true }).afterClosed(),
    ).then((v) => v === true);
  }

  // Resolves the trimmed value, or null when cancelled.
  prompt(data: PromptData): Promise<string | null> {
    return firstValueFrom(
      this.dialog.open(PromptDialogComponent, { data, width: '440px', restoreFocus: true }).afterClosed(),
    ).then((v) => (typeof v === 'string' ? v : null));
  }
}
