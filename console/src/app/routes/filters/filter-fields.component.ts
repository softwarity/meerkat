import { Component, computed, model } from '@angular/core';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { Spec } from '../../api.service';
import { argBool, argStr, patchSpec } from '../predicates/args';

// Dedicated editors, one per filter shape. Each takes the filter Spec through a
// model() signal and edits its args in place — no generic type picker, no param
// loop. The type is fixed at add-time (chosen from the phase-grouped menu).

const FIELDS_STYLE = `
  .fields {
    display: grid;
    gap: 4px 14px;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    align-items: start;
  }
  mat-form-field,
  textarea {
    width: 100%;
  }
  mat-checkbox {
    align-self: center;
  }
`;

// name + value, shared by add/set request & response header. add-request-header
// additionally offers "only if not present".
@Component({
  selector: 'app-header-filter',
  imports: [MatCheckboxModule, MatFormFieldModule, MatInputModule],
  styles: [FIELDS_STYLE],
  templateUrl: './filter-fields.component.html',
})
export class HeaderFilterComponent {
  readonly spec = model.required<Spec>();
  protected readonly name = computed(() => argStr(this.spec(), 'name'));
  protected readonly value = computed(() => argStr(this.spec(), 'value'));
  protected readonly ifNotPresent = computed(() => argBool(this.spec(), 'ifNotPresent'));
  protected set(key: string, v: string | boolean): void {
    this.spec.update((s) => patchSpec(s, key, v === false ? '' : v));
  }
}

// name only — remove request/response header.
@Component({
  selector: 'app-remove-header-filter',
  imports: [MatFormFieldModule, MatInputModule],
  styles: [FIELDS_STYLE],
  template: `
    <div class="fields">
      <mat-form-field>
        <mat-label i18n="@@Header_name">Header name</mat-label>
        <input matInput [value]="name()" (input)="set($any($event.target).value)" />
      </mat-form-field>
    </div>
  `,
})
export class RemoveHeaderFilterComponent {
  readonly spec = model.required<Spec>();
  protected readonly name = computed(() => argStr(this.spec(), 'name'));
  protected set(v: string): void {
    this.spec.update((s) => patchSpec(s, 'name', v));
  }
}

// name + value — set query parameter.
@Component({
  selector: 'app-set-query-param-filter',
  imports: [MatFormFieldModule, MatInputModule],
  styles: [FIELDS_STYLE],
  template: `
    <div class="fields">
      <mat-form-field>
        <mat-label i18n="@@Query_param">Query parameter</mat-label>
        <input matInput [value]="name()" (input)="set('name', $any($event.target).value)" />
      </mat-form-field>
      <mat-form-field>
        <mat-label i18n="@@Value">Value</mat-label>
        <input matInput [value]="value()" (input)="set('value', $any($event.target).value)" />
      </mat-form-field>
    </div>
  `,
})
export class SetQueryParamFilterComponent {
  readonly spec = model.required<Spec>();
  protected readonly name = computed(() => argStr(this.spec(), 'name'));
  protected readonly value = computed(() => argStr(this.spec(), 'value'));
  protected set(key: string, v: string): void {
    this.spec.update((s) => patchSpec(s, key, v));
  }
}

// name only — remove query parameter.
@Component({
  selector: 'app-remove-query-param-filter',
  imports: [MatFormFieldModule, MatInputModule],
  styles: [FIELDS_STYLE],
  template: `
    <div class="fields">
      <mat-form-field>
        <mat-label i18n="@@Query_param">Query parameter</mat-label>
        <input matInput [value]="name()" (input)="set($any($event.target).value)" />
      </mat-form-field>
    </div>
  `,
})
export class RemoveQueryParamFilterComponent {
  readonly spec = model.required<Spec>();
  protected readonly name = computed(() => argStr(this.spec(), 'name'));
  protected set(v: string): void {
    this.spec.update((s) => patchSpec(s, 'name', v));
  }
}

// integer count — strip N leading path segments.
@Component({
  selector: 'app-strip-prefix-filter',
  imports: [MatFormFieldModule, MatInputModule],
  styles: [FIELDS_STYLE],
  template: `
    <div class="fields">
      <mat-form-field>
        <mat-label i18n="@@Segments_to_strip">Segments to strip</mat-label>
        <input matInput type="number" min="0" [value]="parts()" (input)="set($any($event.target).value)" />
      </mat-form-field>
    </div>
  `,
})
export class StripPrefixFilterComponent {
  readonly spec = model.required<Spec>();
  protected readonly parts = computed(() => argStr(this.spec(), 'parts'));
  protected set(v: string): void {
    this.spec.update((s) => patchSpec(s, 'parts', v === '' ? '' : Number(v)));
  }
}

// single string — prepend a path prefix.
@Component({
  selector: 'app-prefix-path-filter',
  imports: [MatFormFieldModule, MatInputModule],
  styles: [FIELDS_STYLE],
  template: `
    <div class="fields">
      <mat-form-field>
        <mat-label i18n="@@Prefix">Prefix</mat-label>
        <input matInput [value]="prefix()" placeholder="/api" (input)="set($any($event.target).value)" />
      </mat-form-field>
    </div>
  `,
})
export class PrefixPathFilterComponent {
  readonly spec = model.required<Spec>();
  protected readonly prefix = computed(() => argStr(this.spec(), 'prefix'));
  protected set(v: string): void {
    this.spec.update((s) => patchSpec(s, 'prefix', v));
  }
}

// regexp + replacement — rewrite the request path.
@Component({
  selector: 'app-rewrite-path-filter',
  imports: [MatFormFieldModule, MatInputModule],
  styles: [FIELDS_STYLE],
  template: `
    <div class="fields">
      <mat-form-field>
        <mat-label i18n="@@Pattern">Pattern</mat-label>
        <input matInput [value]="pattern()" (input)="set('pattern', $any($event.target).value)" />
      </mat-form-field>
      <mat-form-field>
        <mat-label i18n="@@Replacement">Replacement</mat-label>
        <input matInput [value]="replacement()" (input)="set('replacement', $any($event.target).value)" />
      </mat-form-field>
    </div>
  `,
})
export class RewritePathFilterComponent {
  readonly spec = model.required<Spec>();
  protected readonly pattern = computed(() => argStr(this.spec(), 'pattern'));
  protected readonly replacement = computed(() => argStr(this.spec(), 'replacement'));
  protected set(key: string, v: string): void {
    this.spec.update((s) => patchSpec(s, key, v));
  }
}


// integer — force a response status.
@Component({
  selector: 'app-set-status-filter',
  imports: [MatFormFieldModule, MatInputModule],
  styles: [FIELDS_STYLE],
  template: `
    <div class="fields">
      <mat-form-field>
        <mat-label i18n="@@Status_code">Status code</mat-label>
        <input matInput type="number" [value]="status()" placeholder="204" (input)="set($any($event.target).value)" />
      </mat-form-field>
    </div>
  `,
})
export class SetStatusFilterComponent {
  readonly spec = model.required<Spec>();
  protected readonly status = computed(() => argStr(this.spec(), 'status'));
  protected set(v: string): void {
    this.spec.update((s) => patchSpec(s, 'status', v === '' ? '' : Number(v)));
  }
}

// location + optional status — terminal redirect.
@Component({
  selector: 'app-redirect-filter',
  imports: [MatFormFieldModule, MatInputModule],
  styles: [FIELDS_STYLE],
  template: `
    <div class="fields">
      <mat-form-field>
        <mat-label i18n="@@Location">Location</mat-label>
        <input matInput [value]="location()" placeholder="/login" (input)="set('location', $any($event.target).value)" />
      </mat-form-field>
      <mat-form-field>
        <mat-label i18n="@@Status_code">Status code</mat-label>
        <input matInput type="number" [value]="status()" placeholder="302" (input)="setStatus($any($event.target).value)" />
      </mat-form-field>
    </div>
  `,
})
export class RedirectFilterComponent {
  readonly spec = model.required<Spec>();
  protected readonly location = computed(() => argStr(this.spec(), 'location'));
  protected readonly status = computed(() => argStr(this.spec(), 'status'));
  protected set(key: string, v: string): void {
    this.spec.update((s) => patchSpec(s, key, v));
  }
  protected setStatus(v: string): void {
    this.spec.update((s) => patchSpec(s, 'status', v === '' ? '' : Number(v)));
  }
}

// The built-in maintenance answer: just the optional message shown on the page.
@Component({
  selector: 'app-maintenance-filter',
  imports: [MatFormFieldModule, MatInputModule],
  styles: [FIELDS_STYLE],
  template: `
    <div class="fields">
      <mat-form-field>
        <mat-label i18n="@@Message">Message</mat-label>
        <input
          matInput
          i18n-placeholder="@@Back_soon"
          placeholder="Back soon"
          [value]="message()"
          (input)="set('message', $any($event.target).value)"
        />
      </mat-form-field>
    </div>
  `,
})
export class MaintenanceFilterComponent {
  readonly spec = model.required<Spec>();
  protected readonly message = computed(() => argStr(this.spec(), 'message'));
  protected set(key: string, v: string): void {
    this.spec.update((s) => patchSpec(s, key, v));
  }
}
