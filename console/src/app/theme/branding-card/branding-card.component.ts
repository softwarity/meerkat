import { Component, inject, model, output, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatTooltipModule } from '@angular/material/tooltip';

const ACCEPTED = ['image/png', 'image/jpeg', 'image/webp', 'image/svg+xml'];

// Global application identity (THEME-02): name, tagline, and the logo as a
// drop zone whose empty state IS the flow pages' generic placeholder mark.
// Two-way model signals — the page owns persistence.
@Component({
  selector: 'app-branding-card',
  imports: [
    MatButtonModule,
    MatCardModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatTooltipModule,
  ],
  templateUrl: './branding-card.component.html',
  styleUrl: './branding-card.component.scss',
})
export class BrandingCardComponent {
  readonly appName = model.required<string>();
  readonly tagline = model.required<string>();
  readonly logo = model.required<string>();
  readonly save = output<void>();

  protected readonly dragging = signal(false);

  private readonly snack = inject(MatSnackBar);

  protected onLogoFile(ev: Event): void {
    this.readFile((ev.target as HTMLInputElement).files?.[0]);
  }

  protected onDrop(ev: DragEvent): void {
    ev.preventDefault();
    this.dragging.set(false);
    this.readFile(ev.dataTransfer?.files?.[0]);
  }

  private readFile(file: File | undefined): void {
    if (!file) return;
    if (!ACCEPTED.includes(file.type)) {
      this.snack.open(
        $localize`:@@Logo_type_unsupported:Use a png, jpeg, webp or svg image`,
        undefined,
        { duration: 3000 },
      );
      return;
    }
    if (file.size > 200_000) {
      this.snack.open($localize`:@@Logo_too_large:Keep the logo under 200 KiB`, undefined, { duration: 3000 });
      return;
    }
    const reader = new FileReader();
    reader.onload = () => this.logo.set(String(reader.result));
    reader.readAsDataURL(file);
  }
}
