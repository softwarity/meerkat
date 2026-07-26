import { Component, input } from '@angular/core';

// One glyph per ancestry level, drawn left to right in front of a tree row:
// 'continue'         │   an ancestor above still has siblings below
// 'attach-continue'  ├─  this node attaches, and has siblings below
// 'attach-end'       └─  this node attaches as the last child
// 'empty'                that ancestor line is finished
export type TreeGuide = 'continue' | 'attach-continue' | 'attach-end' | 'empty';

// Materializes a hierarchy inside a FLAT table (archway's prefix-tree): the
// host stretches to the row's height and draws the guide lines edge to edge,
// so consecutive rows join into continuous branches.
@Component({
  selector: 'app-tree-prefix',
  styles: [
    `
      :host {
        display: flex;
        align-self: stretch;
        flex: 0 0 auto;
      }
      svg {
        width: 24px;
        height: 100%;
      }
      line {
        stroke: var(--mat-sys-outline-variant);
        stroke-width: 2;
      }
    `,
  ],
  template: `
    @for (g of guides(); track $index) {
      <svg viewBox="0 0 24 52" preserveAspectRatio="none">
        @switch (g) {
          @case ('continue') {
            <line x1="12" y1="0" x2="12" y2="52" />
          }
          @case ('attach-continue') {
            <line x1="12" y1="0" x2="12" y2="52" />
            <line x1="12" y1="26" x2="24" y2="26" />
          }
          @case ('attach-end') {
            <line x1="12" y1="0" x2="12" y2="26" />
            <line x1="12" y1="26" x2="24" y2="26" />
          }
        }
      </svg>
    }
  `,
})
export class TreePrefixComponent {
  readonly guides = input.required<TreeGuide[]>();
}
