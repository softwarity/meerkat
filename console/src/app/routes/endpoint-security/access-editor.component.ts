import { Component, computed, input, output } from '@angular/core';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { Role, User } from '../../api.service';

// The editable, non-optional shape of an access rule inside the editor.
export interface AccessState {
  authenticated: boolean;
  users: string[];
  roles: string[];
}

export function emptyAccess(): AccessState {
  return { authenticated: false, users: [], roles: [] };
}

// Empty means no gateway rule: the request is delegated to the API backend's
// own security, NOT made public.
export function isEmpty(a: AccessState): boolean {
  return !a.authenticated && a.users.length === 0 && a.roles.length === 0;
}

// One access rule, edited the same way for the whole route and for a single
// endpoint (RBAC-06/07): an "authenticated" checkbox, plus users and roles
// chip-selects. Naming any user or role forces authentication (the box checks
// and locks), but users and roles are chosen independently.
@Component({
  selector: 'app-access-editor',
  imports: [MatCheckboxModule, MatFormFieldModule, MatSelectModule],
  template: `
    <mat-checkbox
      [checked]="value().authenticated"
      [disabled]="locked()"
      (change)="patch({ authenticated: $event.checked })"
    >
      <span i18n="@@Authenticated">Authenticated</span>
    </mat-checkbox>

    <mat-form-field class="field" subscriptSizing="dynamic">
      <mat-label i18n="@@Users_any_of">Users (any one grants access)</mat-label>
      <mat-select multiple [value]="value().users" (selectionChange)="patch({ users: $event.value })">
        @for (u of users(); track u.id) {
          <mat-option [value]="u.username">
            <span class="opt-main">{{ u.username }}</span>
            @if (u.email) {
              <span class="opt-sub">{{ u.email }}</span>
            }
          </mat-option>
        }
      </mat-select>
    </mat-form-field>

    <mat-form-field class="field" subscriptSizing="dynamic">
      <mat-label i18n="@@Roles_any_of">Roles (any one grants access)</mat-label>
      <mat-select multiple [value]="value().roles" (selectionChange)="patch({ roles: $event.value })">
        @for (r of roles(); track r.id) {
          <mat-option [value]="r.name">
            <span class="opt-main">{{ r.name }}</span>
            @if (r.description) {
              <span class="opt-sub">{{ r.description }}</span>
            }
          </mat-option>
        }
      </mat-select>
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
  readonly valueChange = output<AccessState>();

  // Authentication is forced (and its box locked) as soon as a user or role is
  // named: those already require a session.
  protected readonly locked = computed(() => this.value().users.length > 0 || this.value().roles.length > 0);

  protected patch(p: Partial<AccessState>): void {
    const next = { ...this.value(), ...p };
    const authenticated = next.authenticated || next.users.length > 0 || next.roles.length > 0;
    this.valueChange.emit({ authenticated, users: next.users, roles: next.roles });
  }
}
