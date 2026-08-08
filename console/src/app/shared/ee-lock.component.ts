import { Component, input } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { RouterLink } from '@angular/router';

// The cap on a control this installation has not unlocked.
//
// Put it INSIDE the element that carries `ee-feature`, next to its label. The
// CSS in styles/_modes.scss does the rest: the block goes inert and dims,
// this badge stays lit and clickable, and the whole thing disappears once the
// feature is on - a control someone paid for is just a control.
//
// It exists as a component rather than a CSS pseudo-element for one reason: a
// ::after cannot carry a Material tooltip, and a native title attribute pops
// up over everything around it (the routes table taught us that).
@Component({
  selector: 'app-ee-lock',
  imports: [MatIconModule, MatTooltipModule, RouterLink],
  template: `
    <a class="lock" routerLink="/license" [matTooltip]="why()" (click)="$event.stopPropagation()">
      <mat-icon>workspace_premium</mat-icon>
      <span i18n="@@Enterprise">Enterprise</span>
    </a>
  `,
  styles: [
    `
      :host {
        display: inline-flex;
        vertical-align: middle;
      }
      .lock {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        padding: 1px 8px 1px 6px;
        border-radius: 999px;
        border: 1px solid var(--mat-sys-tertiary);
        color: var(--mat-sys-tertiary);
        font-size: 0.68rem;
        font-weight: 700;
        letter-spacing: 0.04em;
        text-decoration: none;
        white-space: nowrap;
      }
      .lock:hover {
        background: color-mix(in srgb, var(--mat-sys-tertiary) 14%, transparent);
      }
      .lock mat-icon {
        font-size: 14px;
        width: 14px;
        height: 14px;
      }
    `,
  ],
})
export class EeLockComponent {
  // The feature key, matching internal/features. It is what the CSS keys the
  // badge's own visibility on, so it must be set even though the component
  // itself never reads it.
  readonly feature = input.required<string>();
  // What this would do, in one sentence. Shown on hover, because a badge that
  // only says "Enterprise" tells someone they cannot have something without
  // ever saying what.
  readonly why = input('');
}
