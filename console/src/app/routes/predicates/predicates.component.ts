import { Component, computed, input, model } from '@angular/core';
import { type FormValueControl, type ValidationError } from '@angular/forms/signals';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatSidenavModule } from '@angular/material/sidenav';
import { CatalogEntry, Spec } from '../../api.service';
import { brickDoc } from '../brick-docs';
import { humanize } from './args';
import { PredicateItemComponent } from './predicate-item.component';

// Catalog order: the everyday matchers first, the specialized ones after.
const PREFERRED_ORDER = [
  'path',
  'host',
  'method',
  'header',
  'cookie',
  'query',
  'remote-addr',
  'x-forwarded-remote-addr',
  'after',
  'before',
  'between',
  'weight',
];

// Predicates are ANDed, so a second path/host/... can never widen a route (OR
// lives INSIDE the predicate: several patterns in one path). Only the named
// matchers make sense several times (two different headers, cookies, params).
const MULTI_INSTANCE = ['header', 'cookie', 'query'];

// Predicates section — an addable list; "Add" opens a right-hand drawer with
// the whole catalog, a real explanation per entry. Predicates are ANDed
// (order carries no meaning, no reorder); single-instance types gray out
// once present. A FormValueControl bound with [formField].
@Component({
  selector: 'app-predicates',
  imports: [MatButtonModule, MatIconModule, MatSidenavModule, PredicateItemComponent],
  styles: [
    `
      :host {
        display: block;
        height: 100%;
      }
      .pal-wrap {
        height: 100%;
        background: transparent;
      }
      .pal {
        width: 380px;
        padding: 16px 14px;
        display: block;
      }
      .pal h4 {
        margin: 0 0 10px;
        font-size: 0.78rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: var(--mat-sys-on-surface-variant);
      }
      .bar {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 12px;
      }
      .intro {
        flex: 1;
        margin: 0;
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.9rem;
      }
      .empty {
        margin: 0 0 12px;
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.85rem;
        font-style: italic;
      }
      .error {
        margin: 0 0 12px;
        color: var(--mat-sys-error);
        font-size: 0.85rem;
      }
      .cat-entry {
        display: flex;
        gap: 8px;
        align-items: flex-start;
        text-align: left;
        width: 100%;
        padding: 8px 10px;
        border: 0;
        border-radius: 8px;
        background: none;
        color: var(--mat-sys-on-surface);
        cursor: pointer;
        font: inherit;
      }
      .cat-entry:hover:not(:disabled) {
        background: var(--mat-sys-surface-container-high);
      }
      .cat-entry:disabled {
        opacity: 0.4;
        cursor: default;
      }
      .cat-entry mat-icon {
        flex-shrink: 0;
        margin-top: 1px;
        font-size: 19px;
        width: 19px;
        height: 19px;
        color: var(--mat-sys-primary);
      }
      .b-lines {
        display: grid;
        line-height: 1.35;
      }
      .b-doc {
        font-size: 0.74rem;
        color: var(--mat-sys-on-surface-variant);
        white-space: normal;
      }
    `,
  ],
  template: `
    <mat-drawer-container class="pal-wrap" hasBackdrop="true">
      <mat-drawer #pal position="end" mode="over" class="pal">
        <h4 i18n="@@Add_predicate">Add predicate</h4>
        @for (e of ordered(); track e.type) {
          <button class="cat-entry" [disabled]="taken(e.type)" (click)="add(e.type); pal.close()">
            <mat-icon>add</mat-icon>
            <span class="b-lines">
              <span>{{ label(e.type) }}</span>
              <span class="b-doc">{{ doc(e.type) }}</span>
            </span>
          </button>
        }
      </mat-drawer>
      <mat-drawer-content>
        <div class="bar">
          <p class="intro" i18n="@@Predicates_all_must_match">Predicates: all must match (logical AND).</p>
          <button matButton="tonal" (click)="pal.open()">
            <mat-icon>add</mat-icon>
            <ng-container i18n="@@Add">Add</ng-container>
          </button>
        </div>

        @for (e of errors(); track e.kind) {
          <p class="error">{{ e.message }}</p>
        }

        @for (p of value(); track $index; let i = $index) {
          <app-predicate-item [spec]="p" (specChange)="updateAt(i, $event)" (removed)="removeAt(i)" />
        } @empty {
          <p class="empty" i18n="@@No_predicates_yet_the_route_matches_nothing">
            No predicates yet: the route matches nothing.
          </p>
        }
      </mat-drawer-content>
    </mat-drawer-container>
  `,
})
export class PredicatesComponent implements FormValueControl<Spec[]> {
  readonly value = model<Spec[]>([]);
  readonly entries = input.required<CatalogEntry[]>();
  readonly errors = input<readonly ValidationError.WithOptionalFieldTree[]>([]);

  protected readonly ordered = computed(() => {
    const rank = (t: string) => {
      const i = PREFERRED_ORDER.indexOf(t);
      return i < 0 ? PREFERRED_ORDER.length : i;
    };
    return [...this.entries()].sort((a, b) => rank(a.type) - rank(b.type) || a.type.localeCompare(b.type));
  });

  protected label(value: string): string {
    return humanize(value);
  }

  protected doc(type: string): string {
    return brickDoc(type) || this.entries().find((e) => e.type === type)?.doc || '';
  }

  // Single-instance types gray out once present (ANDing a second one could
  // only narrow the match to nothing).
  protected taken(type: string): boolean {
    return !MULTI_INSTANCE.includes(type) && this.value().some((s) => s.type === type);
  }

  protected add(type: string): void {
    this.value.update((list) => [...list, { type }]);
  }

  protected updateAt(index: number, spec: Spec): void {
    this.value.update((list) => list.map((s, i) => (i === index ? spec : s)));
  }

  protected removeAt(index: number): void {
    this.value.update((list) => list.filter((_, i) => i !== index));
  }
}
