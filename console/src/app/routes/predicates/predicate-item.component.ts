import { Component, computed, input, model, output } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { Spec } from '../../api.service';
import { humanize } from './args';
import {
  AddrPredicateComponent,
  DatetimePredicateComponent,
  ListPredicateComponent,
  MatcherPredicateComponent,
  MethodPredicateComponent,
  WeightPredicateComponent,
} from './predicate-fields.component';

// type -> which dedicated editor renders it: the 12 predicate types collapse
// onto 6 shapes (a matcher is a matcher, whatever it reads).
const KIND: Record<string, string> = {
  path: 'list',
  host: 'list',
  method: 'method',
  header: 'matcher',
  cookie: 'matcher',
  query: 'matcher',
  'remote-addr': 'addr',
  'x-forwarded-remote-addr': 'addr',
  after: 'datetime',
  before: 'datetime',
  between: 'datetime',
  weight: 'weight',
};

// One predicate in the list: a header (the type + remove; predicates are
// ANDed, so no reorder controls) over the dedicated editor for its type.
@Component({
  selector: 'app-predicate-item',
  imports: [
    MatButtonModule,
    MatIconModule,
    ListPredicateComponent,
    MethodPredicateComponent,
    MatcherPredicateComponent,
    AddrPredicateComponent,
    DatetimePredicateComponent,
    WeightPredicateComponent,
  ],
  styles: [
    `
      :host {
        display: block;
        border: 1px solid var(--mat-sys-outline-variant);
        border-radius: 10px;
        padding: 10px 12px 4px;
        margin-bottom: 10px;
        background: var(--mat-sys-surface-container-low);
      }
      .head {
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 4px;
      }
      .type {
        font-size: 0.9rem;
        font-weight: 500;
      }
      .spacer {
        flex: 1;
      }
      .head button {
        --mat-icon-button-state-layer-size: 32px;
      }
    `,
  ],
  template: `
    <div class="head">
      <span class="type">{{ label() }}</span>
      <span class="spacer"></span>
      <button matIconButton (click)="removed.emit()" i18n-aria-label="@@Remove" aria-label="Remove">
        <mat-icon>close</mat-icon>
      </button>
    </div>

    @switch (kind()) {
      @case ('list') {
        <app-list-predicate [spec]="spec()" (specChange)="spec.set($event)" />
      }
      @case ('method') {
        <app-method-predicate [spec]="spec()" (specChange)="spec.set($event)" />
      }
      @case ('matcher') {
        <app-matcher-predicate [spec]="spec()" (specChange)="spec.set($event)" />
      }
      @case ('addr') {
        <app-addr-predicate [spec]="spec()" (specChange)="spec.set($event)" />
      }
      @case ('datetime') {
        <app-datetime-predicate [spec]="spec()" (specChange)="spec.set($event)" />
      }
      @case ('weight') {
        <app-weight-predicate [spec]="spec()" (specChange)="spec.set($event)" />
      }
    }
  `,
})
export class PredicateItemComponent {
  readonly spec = model.required<Spec>();
  readonly doc = input('');
  readonly removed = output<void>();

  protected readonly kind = computed(() => KIND[this.spec().type] ?? 'matcher');
  protected readonly label = computed(() => humanize(this.spec().type));
}
