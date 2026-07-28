import { Component, computed, inject, signal } from '@angular/core';
import { MAT_DIALOG_DATA, MatDialogModule } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatExpansionModule } from '@angular/material/expansion';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatTooltipModule } from '@angular/material/tooltip';
import { ApiService, IdentityForward, IdentityPreview } from '../api.service';

// What the route's identity forwarding actually sends upstream, for a FICTIONAL
// caller the server picks (never the real session, and never values chosen by
// the console: a signed preview is a real token). Opened from the Identity
// section, it previews the DRAFT config — no save needed.
export interface IdentityPreviewData {
  routeName: string;
  identity: IdentityForward;
}

@Component({
  selector: 'app-identity-preview-dialog',
  imports: [
    MatButtonModule,
    MatDialogModule,
    MatExpansionModule,
    MatIconModule,
    MatProgressBarModule,
    MatTooltipModule,
  ],
  styleUrl: './identity-preview-dialog.component.scss',
  templateUrl: './identity-preview-dialog.component.html',
})
export class IdentityPreviewDialogComponent {
  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);
  private readonly input = inject<IdentityPreviewData>(MAT_DIALOG_DATA);

  protected readonly loading = signal(true);
  protected readonly error = signal('');
  protected readonly data = signal<IdentityPreview | null>(null);
  protected readonly claimsJson = computed(() => JSON.stringify(this.data()?.claims ?? {}, null, 2));

  constructor() {
    this.api.previewIdentity(this.input.routeName, this.input.identity).subscribe({
      next: (d) => {
        this.data.set(d);
        this.loading.set(false);
      },
      error: (err: unknown) => {
        const e = err as { error?: { error?: string } };
        this.error.set(
          typeof e?.error?.error === 'string' ? e.error.error : $localize`:@@Request_failed:Request failed`,
        );
        this.loading.set(false);
      },
    });
  }

  protected copy(text: string): void {
    void navigator.clipboard?.writeText(text);
    this.snack.open($localize`:@@Copied:Copied`, undefined, { duration: 1500 });
  }
}
