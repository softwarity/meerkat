import { Component, computed, input, output } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatDividerModule } from '@angular/material/divider';
import { MatIconModule } from '@angular/material/icon';
import { MatMenuModule } from '@angular/material/menu';
import { MatTooltipModule } from '@angular/material/tooltip';
import { Theme } from '../../api.service';

// Distance between two adjacent pills, as a % of the rail width — enough to
// spread across the width without cropping, but kept tight.
const STEP = 8;

// Fixed px from the centre to the FIRST pill on each side, carving a notch that
// clears the nav block (so the adjacent pills aren't cropped) without widening
// every other gap. Further pills add STEP on top.
const NAV_CLEAR = 112;

// The theme picker, overlaid in the gap between the two preview panes (no top
// row). An INFINITE carousel: each pill is placed by its shortest circular
// distance from the selected theme (as a % of the width), so stepping past the
// end wraps around. The nav block straddles both panes, vertically centred on
// the pills; the selected theme's palette rides on top of it as a clickable
// pill — clicking it makes that theme live. Between the arrows: "+" (duplicate
// + start-from-a-preset) and delete. Pure positioning — never touches the
// preview width that drives the scale.
@Component({
  selector: 'app-theme-carousel',
  imports: [MatButtonModule, MatDividerModule, MatIconModule, MatMenuModule, MatTooltipModule],
  templateUrl: './theme-carousel.component.html',
  styleUrl: './theme-carousel.component.scss',
})
export class ThemeCarouselComponent {
  readonly themes = input.required<Theme[]>();
  readonly presets = input<Theme[]>([]);
  readonly selectedId = input.required<string>();

  readonly pick = output<Theme>();
  readonly activateTheme = output<Theme>();
  readonly duplicateTheme = output<Theme>();
  readonly removeTheme = output<Theme>();
  readonly createPreset = output<Theme>();

  protected readonly tipActivate = $localize`:@@Set_active:Set active`;
  protected readonly tipActive = $localize`:@@Active_theme:Active theme`;

  protected readonly selected = computed(
    () => this.themes().find((t) => t.id === this.selectedId()) ?? null,
  );

  private readonly index = computed(() => {
    const i = this.themes().findIndex((t) => t.id === this.selectedId());
    return i < 0 ? 0 : i;
  });

  // Shortest signed distance of pill i from the selected one, wrapping the ring.
  protected offset(i: number): number {
    const n = this.themes().length;
    if (!n) return 0;
    const raw = (((i - this.index()) % n) + n) % n;
    return raw > n / 2 ? raw - n : raw;
  }

  protected leftFor(o: number): string {
    if (o === 0) return '50%';
    const s = o > 0 ? 1 : -1;
    // First pill sits at a fixed distance (clears the nav); the rest step in %.
    return `calc(50% + ${s * NAV_CLEAR}px + ${(o - s) * STEP}%)`;
  }

  protected prev(): void {
    const n = this.themes().length;
    if (n) this.pick.emit(this.themes()[(this.index() - 1 + n) % n]);
  }

  protected next(): void {
    const n = this.themes().length;
    if (n) this.pick.emit(this.themes()[(this.index() + 1) % n]);
  }
}
