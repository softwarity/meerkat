import {
  Component,
  ElementRef,
  computed,
  effect,
  inject,
  input,
  signal,
  viewChild,
} from '@angular/core';
import { DomSanitizer, SafeResourceUrl } from '@angular/platform-browser';
import { MatIconModule } from '@angular/material/icon';
import { CSS_VARS } from '../theme-tokens';

// The live preview: the gateway-rendered flow-page specimen, dark and light
// SIDE BY SIDE, each scaled from its logical 1280×800 viewport to fit — the
// point is to see the whole page. Palette/branding edits and token highlights
// are pushed into both frames over postMessage, no reload.
@Component({
  selector: 'app-theme-preview',
  imports: [MatIconModule],
  templateUrl: './theme-preview.component.html',
  styleUrl: './theme-preview.component.scss',
})
export class ThemePreviewComponent {
  readonly themeId = input.required<string>();
  readonly version = input.required<number>();
  readonly dark = input.required<Record<string, string>>();
  readonly light = input.required<Record<string, string>>();
  readonly brandName = input.required<string>();
  readonly brandTagline = input.required<string>();
  readonly brandLogo = input.required<string>();
  readonly flat = input(false); // flat design → --mk-glow 0, effects off
  readonly highlight = input.required<string>(); // a --mk-* var, or ''

  private readonly sanitizer = inject(DomSanitizer);
  private readonly frames = new Set<HTMLIFrameElement>();

  private readonly hostWidth = signal(0);
  private readonly host = viewChild<ElementRef<HTMLDivElement>>('duo');
  private observed?: HTMLDivElement;

  // Stacked panes, deliberately kept SCALED DOWN (capped width): the point is
  // an at-a-glance look, not a full-size page.
  protected readonly scale = computed(() => {
    const pane = Math.min(this.hostWidth(), 860);
    return pane > 0 ? pane / 1280 : 0.3;
  });
  protected readonly paneWidth = computed(() => Math.round(1280 * this.scale()));
  protected readonly paneHeight = computed(() => Math.round(640 * this.scale()));

  protected readonly darkUrl = computed(() => this.url('dark'));
  protected readonly lightUrl = computed(() => this.url('light'));

  constructor() {
    effect(() => {
      const el = this.host()?.nativeElement;
      if (!el || el === this.observed) return;
      this.observed = el;
      this.hostWidth.set(el.clientWidth);
      new ResizeObserver(() => this.hostWidth.set(el.clientWidth)).observe(el);
    });
    effect(() =>
      this.push(
        this.dark(),
        this.light(),
        this.brandName(),
        this.brandTagline(),
        this.brandLogo(),
        this.flat(),
      ),
    );
    effect(() => this.pushHighlight(this.highlight()));
  }

  protected frameReady(ev: Event): void {
    this.frames.add(ev.target as HTMLIFrameElement);
    this.push(
      this.dark(),
      this.light(),
      this.brandName(),
      this.brandTagline(),
      this.brandLogo(),
      this.flat(),
    );
  }

  private url(scheme: 'dark' | 'light'): SafeResourceUrl | null {
    const id = this.themeId();
    if (!id) return null;
    const raw = `/api/themes/${encodeURIComponent(id)}/preview?scheme=${scheme}&v=${this.version()}`;
    return this.sanitizer.bypassSecurityTrustResourceUrl(raw);
  }

  private post(message: Record<string, unknown>): void {
    for (const frame of this.frames) {
      if (!frame.isConnected) {
        this.frames.delete(frame);
        continue;
      }
      frame.contentWindow?.postMessage({ type: 'meerkat-theme', ...message }, location.origin);
    }
  }

  private push(
    dark: Record<string, string>,
    light: Record<string, string>,
    name: string,
    tagline: string,
    logo: string,
    flat: boolean,
  ): void {
    const vars: Record<string, string> = {};
    for (const [key, cssVar] of Object.entries(CSS_VARS)) {
      // Palettes come complete from the API; a token mid-typing may be empty —
      // leave the frame's current value rather than inventing one.
      if (!light[key] || !dark[key]) continue;
      vars[cssVar] = `light-dark(${light[key]}, ${dark[key]})`;
    }
    // The flat-design switch: 0 collapses every decorative effect at once.
    vars['--mk-glow'] = flat ? '0' : '1';
    this.post({ vars, brand: { name, tagline, logo } });
  }

  private pushHighlight(cssVar: string): void {
    this.post({ highlight: cssVar });
  }
}
