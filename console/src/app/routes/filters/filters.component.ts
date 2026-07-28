import { Component, computed, input, linkedSignal, model } from '@angular/core';
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
  styleUrl: './filters.component.scss',
  templateUrl: './filters.component.html',
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

  // Nothing posed in this phase? Open the palette straight away — an empty
  // section has nothing to read, and the next move is always "add one". It
  // stays closable (openedChange writes back), and reseeds when the phase
  // empties or gets its first modifier.
  protected readonly palOpen = linkedSignal(() => this.indexed().length === 0);

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
