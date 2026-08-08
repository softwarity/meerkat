import { Component, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatDialogModule } from '@angular/material/dialog';
import { MatExpansionModule } from '@angular/material/expansion';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatTooltipModule } from '@angular/material/tooltip';
import { ApiService, SigningKeys } from '../api.service';

// The identity JWT signing keys (signed-jwt): the JWKS the backends should
// verify against (the recommended path), plus each algorithm's PUBLIC key as a
// collapsed static fallback, and a rotate button. Reached from the Routes page.
// Private keys stay on the server - only public halves are shown.
@Component({
  selector: 'app-signing-keys-dialog',
  imports: [
    MatButtonModule,
    MatDialogModule,
    MatExpansionModule,
    MatIconModule,
    MatProgressBarModule,
    MatTooltipModule,
  ],
  styleUrl: './signing-keys-dialog.component.scss',
  templateUrl: './signing-keys-dialog.component.html',
})
export class SigningKeysDialogComponent {
  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);

  protected readonly loading = signal(true);
  protected readonly renewing = signal(false);
  protected readonly confirming = signal(false);
  protected readonly data = signal<SigningKeys | null>(null);

  constructor() {
    this.reload();
  }

  private reload(): void {
    this.loading.set(true);
    this.api.getSigningKeys().subscribe({
      next: (d) => {
        this.data.set(d);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  protected copy(text: string): void {
    void navigator.clipboard?.writeText(text);
    this.snack.open($localize`:@@Copied:Copied`, undefined, { duration: 1500 });
  }

  protected renew(): void {
    this.renewing.set(true);
    this.confirming.set(false);
    this.api.renewSigningKeys().subscribe({
      next: (d) => {
        this.data.set(d);
        this.renewing.set(false);
        this.snack.open($localize`:@@Signing_keys_rotated:Signing keys rotated`, undefined, { duration: 2500 });
      },
      error: () => {
        this.renewing.set(false);
        this.snack.open($localize`:@@Request_failed:Request failed`, undefined, { duration: 3000 });
      },
    });
  }
}
