import { Component, computed, model } from '@angular/core';
import { MatAutocompleteModule } from '@angular/material/autocomplete';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { RespondEditorComponent } from './respond-editor.component';
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

// What an answer is usually made of. Offered rather than imposed: the list
// covers what people actually write, and anything else can still be typed —
// a gateway that only knows six content types would be wrong the first time
// someone answers a protobuf.
// Value first, meaning UNDER it. Side by side, in a field this narrow, both
// wrapped over three lines and neither could be read; stacked, the value is
// scannable and the sentence has the width it needs. The charset is dropped
// from the suggestions for the same reason - it can still be typed.
const CONTENT_TYPES: { value: string; what: string }[] = [
  { value: 'application/json', what: 'What an API answers' },
  { value: 'text/plain', what: 'A bare value: a name, a token' },
  { value: 'text/html', what: 'A page or a fragment' },
  { value: 'application/problem+json', what: 'A JSON error (RFC 9457)' },
  { value: 'application/xml', what: 'XML' },
  { value: 'text/csv', what: 'CSV' },
  { value: 'application/javascript', what: 'A small script to inject' },
];

const STATUS_CODES: { value: string; what: string }[] = [
  { value: '200', what: 'OK — here is the answer' },
  { value: '201', what: 'Created' },
  { value: '202', what: 'Accepted — handled later' },
  { value: '204', what: 'No Content — nothing to send back' },
  { value: '400', what: 'Bad Request' },
  { value: '401', what: 'Unauthorized — sign in first' },
  { value: '403', what: 'Forbidden — signed in, not allowed' },
  { value: '404', what: 'Not Found' },
  { value: '410', what: 'Gone — it existed, it will not come back' },
  { value: '429', what: 'Too Many Requests' },
  { value: '500', what: 'Internal Server Error' },
  { value: '503', what: 'Service Unavailable' },
];

// Respond: the template IS the filter, so it gets the room a template needs —
// a full-width monospace box rather than a one-line input squeezed beside the
// content type.
//
// Every example lives in TypeScript, not in the template: Angular reads { and }
// as control-flow blocks, so a literal {{json .Username}} written inline turns
// into a parse error three lines further down (NG5002, and the message points
// at a <textarea> that is perfectly fine).
@Component({
  selector: 'app-respond-filter',
  imports: [MatAutocompleteModule, MatFormFieldModule, MatInputModule, RespondEditorComponent],
  styles: [
    FIELDS_STYLE,
    `
      .body {
        grid-column: 1 / -1;
      }
      .body textarea {
        font-family: var(--mk-mono);
        font-size: 0.82rem;
        line-height: 1.5;
      }
      .vars {
        margin: 12px 0 4px;
        font-size: 0.78rem;
        line-height: 1.6;
        color: var(--mat-sys-on-surface-variant);
        max-width: 78ch;
      }
      .vars p {
        margin: 0 0 8px;
      }
      .vars .lead {
        color: var(--mat-sys-on-surface);
      }
      .vars dl {
        margin: 0 0 8px;
        display: grid;
        gap: 3px 0;
      }
      .vars dt {
        margin-top: 5px;
      }
      .vars dd {
        margin: 0 0 0 14px;
      }
      .vars code {
        font-family: var(--mk-mono);
        background: var(--mat-sys-surface-container-high);
        border-radius: 4px;
        padding: 1px 5px;
      }
    `,
  ],
  template: `
    <div class="fields">
      <!-- What the answer IS comes before what it says: the type and the code
           are decided once, the body is written after. -->
      <mat-form-field>
        <mat-label>Content type</mat-label>
        <input
          matInput
          [matAutocomplete]="ct"
          placeholder="application/json"
          [value]="contentType()"
          (input)="set('contentType', $any($event.target).value)"
        />
        <mat-autocomplete
          #ct="matAutocomplete"
          panelWidth="300px"
          class="stacked-options"
          (optionSelected)="set('contentType', $event.option.value)"
        >
          @for (o of contentTypes; track o.value) {
            <mat-option [value]="o.value">
              <span class="opt-value">{{ o.value }}</span>
              <span class="opt-what">{{ o.what }}</span>
            </mat-option>
          }
        </mat-autocomplete>
      </mat-form-field>
      <mat-form-field>
        <mat-label>Status code</mat-label>
        <input
          matInput
          inputmode="numeric"
          [matAutocomplete]="sc"
          placeholder="200"
          [value]="status()"
          (input)="setStatus($any($event.target).value)"
        />
        <mat-autocomplete
          #sc="matAutocomplete"
          panelWidth="300px"
          class="stacked-options"
          (optionSelected)="setStatus($event.option.value)"
        >
          @for (o of statusCodes; track o.value) {
            <mat-option [value]="o.value">
              <span class="opt-value">{{ o.value }}</span>
              <span class="opt-what">{{ o.what }}</span>
            </mat-option>
          }
        </mat-autocomplete>
      </mat-form-field>

      <div class="body">
        <app-respond-editor [value]="body()" (changed)="set('body', $event)" />
        <div class="vars">
          <p class="lead">
            The answer is written literally, and anything between
            <code>&#123;&#123;</code> and <code>&#125;&#125;</code> is replaced by something about the caller.
            Everything else is sent as typed.
          </p>
          <dl>
            <dt><code>{{ GOOD }}</code></dt>
            <dd>
              the caller's name, <strong>with its quotes and escaping</strong>. Always through
              <code>json</code> — <code>{{ BAD }}</code> looks equivalent and breaks the day a name holds a
              quote, which is a name that comes from a directory, not from you.
            </dd>
            <dt><code>{{ WRAP }}</code></dt>
            <dd>the roles as one-key objects: <code>{{ WRAP_OUT }}</code>. Empty list if the caller holds none.</dd>
            <dt><code>{{ JOIN }}</code></dt>
            <dd>the roles as one string: <code>ROLE_A,ROLE_B</code>.</dd>
            <dt><code>{{ IFELSE }}</code></dt>
            <dd>two answers in one route: nobody is signed in when the route has no gateway rule.</dd>
          </dl>
          <p class="also">
            Also available: <code>.UserID</code> <code>.Fullname</code> <code>.Email</code> <code>.Tenant</code>
            <code>.TenantID</code> <code>.Timezone</code> <code>.Roles</code>. For a shape none of the above
            covers, loop: <code>{{ LOOP }}</code> — where <code>{{ COMMA }}</code> writes the separating comma
            (<code>$i</code> is the index, zero is false, so the first element gets none — JSON forbids a
            trailing one).
          </p>
        </div>
      </div>
    </div>
  `,
})
export class RespondFilterComponent {
  readonly spec = model.required<Spec>();
  protected readonly contentTypes = CONTENT_TYPES;
  protected readonly statusCodes = STATUS_CODES;
  protected readonly EXAMPLE = '{"name": {{json .Username}}, "authorities": {{json (wrap "authority" .Roles)}}}';
  protected readonly GOOD = '{{json .Username}}';
  protected readonly BAD = '"{{.Username}}"';
  protected readonly JOIN = '{{join "," .Roles}}';
  protected readonly WRAP = '{{json (wrap "authority" .Roles)}}';
  protected readonly WRAP_OUT = '[{"authority":"ROLE_A"},{"authority":"ROLE_B"}]';
  protected readonly IFELSE = '{{if .SignedIn}}…{{else}}…{{end}}';
  protected readonly COMMA = '{{if $i}},{{end}}';
  protected readonly LOOP = '{{range $i, $r := .Roles}}…{{end}}';
  protected readonly body = computed(() => argStr(this.spec(), 'body'));
  protected readonly contentType = computed(() => argStr(this.spec(), 'contentType'));
  protected readonly status = computed(() => argStr(this.spec(), 'status'));
  protected set(key: string, v: string): void {
    this.spec.update((s) => patchSpec(s, key, v));
  }
  protected setStatus(v: string): void {
    this.spec.update((s) => patchSpec(s, 'status', v === '' ? '' : Number(v)));
  }
}
