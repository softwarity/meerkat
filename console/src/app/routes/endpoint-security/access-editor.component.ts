import { Component, computed, input, output } from '@angular/core';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { AccessLevel, Role, Tenant, User } from '../../api.service';

// The editable, non-optional shape of an access rule inside the editor.
export interface AccessState {
  level: AccessLevel;
  tenants: string[];
  roles: string[];
  users: string[];
}

export function emptyAccess(): AccessState {
  return { level: '', tenants: [], roles: [], users: [] };
}

// Empty means no gateway rule: the request is delegated to the upstream's own
// security, NOT made public.
export function isEmpty(a: AccessState): boolean {
  return a.level === '' && a.roles.length === 0 && a.users.length === 0;
}

// The belonging axis, in order. Each entry says what it REQUIRES, because the
// difference that catches people out is not between the labels but between
// what they let through: "delegated" and "public" both answer everyone, yet
// only one of them is a decision.
export const ACCESS_LEVELS: { value: AccessLevel; label: string; hint: string }[] = [
  {
    value: '',
    label: $localize`:@@Access_delegated:Delegated`,
    hint: $localize`:@@Access_delegated_hint:Meerkat adds no gate: the upstream keeps its own security. Not the same as public.`,
  },
  {
    value: 'public',
    label: $localize`:@@Access_public:Public`,
    hint: $localize`:@@Access_public_hint:Open to everyone, signed in or not.`,
  },
  {
    value: 'auth',
    label: $localize`:@@Access_authenticated:Signed in`,
    hint: $localize`:@@Access_authenticated_hint:Anyone with an account, including one that belongs to no organisation yet.`,
  },
  {
    value: 'tenant',
    label: $localize`:@@Access_in_an_organisation:In an organisation`,
    hint: $localize`:@@Access_in_an_organisation_hint:An organisation must be active on the session. Turns away an account still awaiting access.`,
  },
  {
    value: 'tenants',
    label: $localize`:@@Access_in_one_of_these:In one of these organisations`,
    hint: $localize`:@@Access_in_one_of_these_hint:The active organisation must be one of those named below.`,
  },
];

// One access rule, edited the same way for the whole route and for a single
// endpoint (RBAC-06/07). TWO AXES, ANDed: the belonging level (plus the named
// organisations when it asks for them), and a role filter evaluated in the
// ACTIVE organisation.
//
// They cross on purpose: the role catalogue is global while groups belong to
// an organisation, so a bare role gate means "an admin of ANY organisation" -
// a cross-org console - while naming organisations too means "an admin OF
// Acme". Named users are the exception, not a level: whoever is listed passes
// whatever the level requires (a service account, a support login, an
// application dedicated to one person).
@Component({
  selector: 'app-access-editor',
  imports: [MatFormFieldModule, MatSelectModule],
  template: `
    <mat-form-field class="field" subscriptSizing="dynamic">
      <mat-label i18n="@@Who_may_call_it">Who may call it</mat-label>
      <mat-select [value]="value().level" (selectionChange)="patch({ level: $event.value })">
        @for (l of levels; track l.value) {
          <mat-option [value]="l.value">
            <span class="opt-main">{{ l.label }}</span>
          </mat-option>
        }
      </mat-select>
      <mat-hint>{{ levelHint() }}</mat-hint>
    </mat-form-field>

    @if (value().level === 'tenants') {
      <mat-form-field class="field" subscriptSizing="dynamic">
        <mat-label i18n="@@Organisations_any_of">Organisations (any one grants access)</mat-label>
        <mat-select multiple [value]="value().tenants" (selectionChange)="patch({ tenants: $event.value })">
          <mat-select-trigger>{{ tenantNames() }}</mat-select-trigger>
          @for (t of tenants(); track t.id) {
            <mat-option [value]="t.id">
              <span class="opt-main">{{ t.name }}</span>
              @if (t.description) {
                <span class="opt-sub">{{ t.description }}</span>
              }
            </mat-option>
          }
        </mat-select>
      </mat-form-field>
    }

    @if (value().level !== '' && value().level !== 'public') {
      <mat-form-field class="field" subscriptSizing="dynamic">
        <mat-label i18n="@@Roles_any_of">Roles (any one grants access)</mat-label>
        <mat-select multiple [value]="value().roles" (selectionChange)="patch({ roles: $event.value })">
          <mat-select-trigger>{{ value().roles.join(', ') }}</mat-select-trigger>
          @for (r of roles(); track r.id) {
            <mat-option [value]="r.name">
              <span class="opt-main">{{ r.name }}</span>
              @if (r.description) {
                <span class="opt-sub">{{ r.description }}</span>
              }
            </mat-option>
          }
        </mat-select>
        <mat-hint i18n="@@Roles_in_active_org_hint">Held in the active organisation. Left empty, any role passes.</mat-hint>
      </mat-form-field>
    }

    <mat-form-field class="field" subscriptSizing="dynamic">
      <mat-label i18n="@@Users_always_allowed">Users always allowed</mat-label>
      <mat-select multiple [value]="value().users" (selectionChange)="patch({ users: $event.value })">
        <mat-select-trigger>{{ value().users.join(', ') }}</mat-select-trigger>
        @for (u of users(); track u.id) {
          <mat-option [value]="u.username">
            <span class="opt-main">{{ u.username }}</span>
            @if (u.email) {
              <span class="opt-sub">{{ u.email }}</span>
            }
          </mat-option>
        }
      </mat-select>
      <mat-hint i18n="@@Users_exception_hint">An exception, not a level: they pass whatever is required above.</mat-hint>
    </mat-form-field>
  `,
  styles: [
    `
      :host {
        display: flex;
        flex-direction: column;
        align-items: stretch;
        gap: 10px;
      }
      .field {
        width: 100%;
      }
      .opt-sub {
        margin-left: 8px;
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.8rem;
      }
    `,
  ],
})
export class AccessEditorComponent {
  readonly value = input.required<AccessState>();
  readonly users = input<User[]>([]);
  readonly roles = input<Role[]>([]);
  readonly tenants = input<Tenant[]>([]);
  readonly valueChange = output<AccessState>();

  protected readonly levels = ACCESS_LEVELS;
  protected readonly levelHint = computed(
    () => ACCESS_LEVELS.find((l) => l.value === this.value().level)?.hint ?? '',
  );
  // Ids are what travels; names are what is read.
  protected readonly tenantNames = computed(() =>
    this.value()
      .tenants.map((id) => this.tenants().find((t) => t.id === id)?.name ?? id)
      .join(', '),
  );

  // Leaving a level drops what only that level meant: named organisations are
  // meaningless anywhere else, and a role filter cannot be evaluated with no
  // organisation to hold it. Keeping them would save a rule the gateway reads
  // differently from the screen that wrote it.
  protected patch(p: Partial<AccessState>): void {
    const next = { ...this.value(), ...p };
    if (next.level !== 'tenants') next.tenants = [];
    if (next.level === '' || next.level === 'public') next.roles = [];
    this.valueChange.emit(next);
  }
}
