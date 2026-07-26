import { Component, computed, model } from '@angular/core';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { Spec } from '../../api.service';
import { argBool, argList, argStr, patchSpec } from './args';
import { StringListComponent } from './string-list.component';

// Dedicated editors, one per predicate shape. Each takes the predicate Spec
// through a model() signal and edits its args in place — the type is fixed at
// add-time (chosen from the catalog menu), same pattern as the filters.

const FIELDS_STYLE = `
  .fields {
    display: grid;
    gap: 4px 14px;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    align-items: start;
  }
  mat-form-field {
    width: 100%;
  }
  mat-checkbox {
    align-self: center;
  }
`;

const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];

// One string-list arg: path (patterns) and host (hosts).
@Component({
  selector: 'app-list-predicate',
  imports: [StringListComponent],
  template: `
    <app-string-list [values]="items()" (valuesChange)="set($event)" [placeholder]="placeholder()" />
  `,
})
export class ListPredicateComponent {
  readonly spec = model.required<Spec>();
  protected readonly key = computed(() => (this.spec().type === 'host' ? 'hosts' : 'patterns'));
  protected readonly items = computed(() => argList(this.spec(), this.key()));
  protected readonly placeholder = computed(() =>
    this.spec().type === 'host' ? '*.example.com' : '/api/**',
  );
  protected set(values: string[]): void {
    this.spec.update((s) => patchSpec(s, this.key(), values));
  }
}

// The HTTP methods, as a multiselect over the standard verbs.
@Component({
  selector: 'app-method-predicate',
  imports: [MatFormFieldModule, MatSelectModule],
  styles: [FIELDS_STYLE],
  template: `
    <div class="fields">
      <mat-form-field>
        <mat-label i18n="@@Methods">Methods</mat-label>
        <mat-select multiple [value]="methods()" (selectionChange)="set($event.value)">
          @for (m of allMethods; track m) {
            <mat-option [value]="m">{{ m }}</mat-option>
          }
        </mat-select>
      </mat-form-field>
    </div>
  `,
})
export class MethodPredicateComponent {
  readonly spec = model.required<Spec>();
  protected readonly allMethods = METHODS;
  protected readonly methods = computed(() => argList(this.spec(), 'methods'));
  protected set(values: string[]): void {
    this.spec.update((s) => patchSpec(s, 'methods', values));
  }
}

// name + optional full-match regexp: header, cookie and query share the shape.
@Component({
  selector: 'app-matcher-predicate',
  imports: [MatFormFieldModule, MatInputModule],
  styles: [FIELDS_STYLE],
  template: `
    <div class="fields">
      <mat-form-field>
        <mat-label i18n="@@Name">Name</mat-label>
        <input matInput [value]="name()" (input)="set('name', $any($event.target).value)" />
      </mat-form-field>
      <mat-form-field>
        <mat-label i18n="@@Value_regexp">Value (regexp)</mat-label>
        <input
          matInput
          i18n-placeholder="@@empty_presence_only"
          placeholder="empty = presence only"
          [value]="regexp()"
          (input)="set('regexp', $any($event.target).value)"
        />
      </mat-form-field>
    </div>
  `,
})
export class MatcherPredicateComponent {
  readonly spec = model.required<Spec>();
  protected readonly name = computed(() => argStr(this.spec(), 'name'));
  protected readonly regexp = computed(() => argStr(this.spec(), 'regexp'));
  protected set(key: string, v: string): void {
    this.spec.update((s) => patchSpec(s, key, v));
  }
}

// CIDR sources; remote-addr additionally offers the trusted-proxy toggle
// (x-forwarded-remote-addr always reads the rightmost X-Forwarded-For entry).
@Component({
  selector: 'app-addr-predicate',
  imports: [MatCheckboxModule, StringListComponent],
  template: `
    <app-string-list [values]="cidrs()" (valuesChange)="set($event)" placeholder="10.0.0.0/8" />
    @if (spec().type === 'remote-addr') {
      <mat-checkbox [checked]="useForwarded()" (change)="setForwarded($event.checked)">
        <ng-container i18n="@@Trust_first_X_Forwarded_For">
          Trust the first X-Forwarded-For entry (only behind a trusted proxy)
        </ng-container>
      </mat-checkbox>
    }
  `,
})
export class AddrPredicateComponent {
  readonly spec = model.required<Spec>();
  protected readonly cidrs = computed(() => argList(this.spec(), 'cidrs'));
  protected readonly useForwarded = computed(() => argBool(this.spec(), 'useForwarded'));
  protected set(values: string[]): void {
    this.spec.update((s) => patchSpec(s, 'cidrs', values));
  }
  protected setForwarded(v: boolean): void {
    this.spec.update((s) => patchSpec(s, 'useForwarded', v ? true : ''));
  }
}

// RFC 3339 bounds: after/before take one datetime, between takes two.
@Component({
  selector: 'app-datetime-predicate',
  imports: [MatFormFieldModule, MatInputModule],
  styles: [FIELDS_STYLE],
  template: `
    <div class="fields">
      @if (spec().type === 'between') {
        <mat-form-field>
          <mat-label i18n="@@From_RFC_3339">From (RFC 3339)</mat-label>
          <input matInput placeholder="2026-01-20T17:42:47+01:00" [value]="dt1()" (input)="set('datetime1', $any($event.target).value)" />
        </mat-form-field>
        <mat-form-field>
          <mat-label i18n="@@To_RFC_3339">To (RFC 3339)</mat-label>
          <input matInput placeholder="2026-01-21T17:42:47+01:00" [value]="dt2()" (input)="set('datetime2', $any($event.target).value)" />
        </mat-form-field>
      } @else {
        <mat-form-field>
          <mat-label i18n="@@Datetime_RFC_3339">Datetime (RFC 3339)</mat-label>
          <input matInput placeholder="2026-01-20T17:42:47+01:00" [value]="dt()" (input)="set('datetime', $any($event.target).value)" />
        </mat-form-field>
      }
    </div>
  `,
})
export class DatetimePredicateComponent {
  readonly spec = model.required<Spec>();
  protected readonly dt = computed(() => argStr(this.spec(), 'datetime'));
  protected readonly dt1 = computed(() => argStr(this.spec(), 'datetime1'));
  protected readonly dt2 = computed(() => argStr(this.spec(), 'datetime2'));
  protected set(key: string, v: string): void {
    this.spec.update((s) => patchSpec(s, key, v));
  }
}

// Canary split: group + weight.
@Component({
  selector: 'app-weight-predicate',
  imports: [MatFormFieldModule, MatInputModule],
  styles: [FIELDS_STYLE],
  template: `
    <div class="fields">
      <mat-form-field>
        <mat-label i18n="@@Group">Group</mat-label>
        <input matInput [value]="group()" (input)="set('group', $any($event.target).value)" />
      </mat-form-field>
      <mat-form-field>
        <mat-label i18n="@@Weight">Weight</mat-label>
        <input matInput type="number" min="1" [value]="weight()" (input)="setWeight($any($event.target).value)" />
      </mat-form-field>
    </div>
  `,
})
export class WeightPredicateComponent {
  readonly spec = model.required<Spec>();
  protected readonly group = computed(() => argStr(this.spec(), 'group'));
  protected readonly weight = computed(() => argStr(this.spec(), 'weight'));
  protected set(key: string, v: string): void {
    this.spec.update((s) => patchSpec(s, key, v));
  }
  protected setWeight(v: string): void {
    const n = parseInt(v, 10);
    this.spec.update((s) => patchSpec(s, 'weight', Number.isFinite(n) ? n : ''));
  }
}
