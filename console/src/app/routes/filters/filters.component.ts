import { Component, computed, input, model } from '@angular/core';
import { type FormValueControl, type ValidationError } from '@angular/forms/signals';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatSidenavModule } from '@angular/material/sidenav';
import { CatalogEntry, Spec } from '../../api.service';
import { PLANNED_MODIFIERS, brickDoc } from '../brick-docs';
import { humanize } from '../predicates/args';
import { FilterItemComponent } from './filter-item.component';

// ONE PHASE of the route's modifiers (incoming request / outgoing response /
// terminal): the section shows and edits only its phase's specs, while the
// bound value stays the route's WHOLE modifier list (indices are global, the
// engine splits by phase at compile time). "Add" opens a right-hand drawer:
// the phase's catalog with a real explanation per entry, plus the PLANNED
// bricks grayed out — what exists and what is coming, in one place.
// A FormValueControl: bound with [formField], schema errors render at the top.
@Component({
  selector: 'app-filters',
  imports: [MatButtonModule, MatIconModule, MatSidenavModule, FilterItemComponent],
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
      button.cat-entry:hover {
        background: var(--mat-sys-surface-container-high);
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
      .planned-title {
        margin: 14px 0 4px;
        padding-top: 10px;
        border-top: 1px solid var(--mat-sys-outline-variant);
        font-size: 0.68rem;
        font-weight: 600;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--mat-sys-secondary);
      }
      .cat-entry.planned {
        opacity: 0.45;
        cursor: default;
      }
    `,
  ],
  template: `
    <mat-drawer-container class="pal-wrap" hasBackdrop="true">
      <mat-drawer #pal position="end" mode="over" class="pal">
        <h4 i18n="@@Add_modifier">Add modifier</h4>
        @for (e of phaseEntries(); track e.type) {
          <button class="cat-entry" (click)="add(e.type); pal.close()">
            <mat-icon>add</mat-icon>
            <span class="b-lines">
              <span>{{ label(e.type) }}</span>
              <span class="b-doc">{{ doc(e.type) }}</span>
            </span>
          </button>
        }
        @if (planned().length) {
          <div class="planned-title" i18n="@@Planned_not_available_yet">Planned (not available yet)</div>
          @for (b of planned(); track b.type) {
            <div class="cat-entry planned">
              <mat-icon>schedule</mat-icon>
              <span class="b-lines">
                <span>{{ label(b.type) }}</span>
                <span class="b-doc">{{ b.doc }}</span>
              </span>
            </div>
          }
        }
      </mat-drawer>
      <mat-drawer-content>
        <div class="bar">
          <p class="intro">{{ intro() }}</p>
          @if (!full()) {
            <button matButton="tonal" (click)="pal.open()">
              <mat-icon>add</mat-icon>
              <ng-container i18n="@@Add">Add</ng-container>
            </button>
          }
        </div>

        @for (e of errors(); track e.kind) {
          <p class="error">{{ e.message }}</p>
        }

        @for (row of indexed(); track row.i; let di = $index) {
          <app-filter-item
            [spec]="row.s"
            (specChange)="updateAt(row.i, $event)"
            [first]="di === 0"
            [last]="di === indexed().length - 1"
            (moveUp)="move(di, -1)"
            (moveDown)="move(di, 1)"
            (removed)="removeAt(row.i)"
          />
        } @empty {
          <p class="empty">{{ empty() }}</p>
        }
      </mat-drawer-content>
    </mat-drawer-container>
  `,
})
export class FiltersComponent implements FormValueControl<Spec[]> {
  readonly value = model<Spec[]>([]);
  readonly entries = input.required<CatalogEntry[]>();
  // 'request' | 'response' | 'terminal' — the ONLY phase this section touches.
  readonly phase = input.required<string>();
  readonly errors = input<readonly ValidationError.WithOptionalFieldTree[]>([]);

  protected readonly phaseEntries = computed(() =>
    this.entries().filter((e) => (e.phase ?? 'request') === this.phase()),
  );
  protected readonly planned = computed(() => PLANNED_MODIFIERS[this.phase()] ?? []);

  // This phase's specs, each keeping its GLOBAL index in the bound list.
  protected readonly indexed = computed(() =>
    this.value()
      .map((s, i) => ({ s, i }))
      .filter(({ s }) => this.typePhase(s.type) === this.phase()),
  );

  // A route has at most one terminal (the engine refuses more).
  protected readonly full = computed(() => this.phase() === 'terminal' && this.indexed().length > 0);

  protected readonly intro = computed(() => {
    switch (this.phase()) {
      case 'request':
        return $localize`:@@Incoming_modifiers_intro:Applied in order to the request before it reaches the service.`;
      case 'response':
        return $localize`:@@Outgoing_modifiers_intro:Applied in order to the response before it reaches the client.`;
      default:
        return $localize`:@@Terminal_modifiers_intro:Answers instead of proxying (redirect, maintenance): at most one, not combined with other modifiers.`;
    }
  });

  protected readonly empty = computed(() =>
    this.phase() === 'terminal'
      ? $localize`:@@No_terminal_the_route_proxies:None: the route proxies to its upstream.`
      : $localize`:@@No_modifiers_yet:No modifiers yet.`,
  );

  private typePhase(type: string): string {
    return this.entries().find((e) => e.type === type)?.phase ?? 'request';
  }

  protected label(value: string): string {
    return humanize(value);
  }

  protected doc(type: string): string {
    return brickDoc(type) || this.entries().find((e) => e.type === type)?.doc || '';
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

  // Reorder WITHIN the phase: swap the two global slots.
  protected move(displayIdx: number, dir: -1 | 1): void {
    const rows = this.indexed();
    const a = rows[displayIdx];
    const b = rows[displayIdx + dir];
    if (!a || !b) return;
    this.value.update((list) => {
      const out = [...list];
      [out[a.i], out[b.i]] = [out[b.i], out[a.i]];
      return out;
    });
  }
}
