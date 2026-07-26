import { Component, input, model, output } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatTooltipModule } from '@angular/material/tooltip';
import { TOKEN_GROUPS } from '../theme-tokens';

// The two palettes of a theme, dark and light side by side, one row per token.
// Hovering a token name tells the page, which highlights the matching elements
// in the preview.
@Component({
  selector: 'app-palette-editor',
  imports: [
    MatButtonModule,
    MatCardModule,
    MatCheckboxModule,
    MatFormFieldModule,
    MatInputModule,
    MatTooltipModule,
  ],
  templateUrl: './palette-editor.component.html',
  styleUrl: './palette-editor.component.scss',
})
export class PaletteEditorComponent {
  readonly dark = model.required<Record<string, string>>();
  readonly light = model.required<Record<string, string>>();
  // Flat design: dropping every decorative flow-page effect (glows + app-name
  // gradient) at once. Surfaced as a "Glow" checkbox (checked = effects on), so
  // stored inverted. Two-way — the page persists it with the theme.
  readonly flat = model<boolean>(false);
  readonly hoverToken = output<string>();
  readonly save = output<void>();
  readonly saving = input(false);

  protected readonly tokenGroups = TOKEN_GROUPS;

  protected setColor(mode: 'dark' | 'light', key: string, value: string): void {
    const target = mode === 'dark' ? this.dark : this.light;
    target.update((m) => ({ ...m, [key]: value.trim().toLowerCase() }));
  }
}
