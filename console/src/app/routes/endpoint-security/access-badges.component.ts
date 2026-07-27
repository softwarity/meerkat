import { Component, computed, input } from '@angular/core';
import { MatBadgeModule } from '@angular/material/badge';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { AccessState, isEmpty } from './access-editor.component';

// The three access dimensions shown at a glance: authentication, named users,
// named roles. Each icon is always present and lights up when its dimension is
// set; the users/roles counts ride as overlay badges (matBadge) so showing a
// number never shifts the layout. All three dim means no gateway rule
// (delegated to the API backend).
@Component({
  selector: 'app-access-badges',
  imports: [MatBadgeModule, MatIconModule, MatTooltipModule],
  template: `
    <span class="set" [class.delegated]="empty()" [matTooltip]="empty() ? delegatedTip : ''">
      <mat-icon class="d d-auth" [class.on]="access().authenticated" [matTooltip]="authTip">lock</mat-icon>
      <mat-icon
        class="d d-users"
        [class.on]="access().users.length > 0"
        [matBadge]="access().users.length"
        [matBadgeHidden]="access().users.length === 0"
        matBadgeSize="small"
        [matTooltip]="usersTip()"
        >group</mat-icon
      >
      <mat-icon
        class="d d-roles"
        [class.on]="access().roles.length > 0"
        [matBadge]="access().roles.length"
        [matBadgeHidden]="access().roles.length === 0"
        matBadgeSize="small"
        [matTooltip]="rolesTip()"
        >badge</mat-icon
      >
    </span>
  `,
  styles: [
    `
      .set {
        display: inline-flex;
        align-items: center;
        gap: 12px;
        padding-right: 6px;
      }
      .d {
        color: var(--mat-sys-outline);
        opacity: 0.5;
        font-size: 20px;
        width: 20px;
        height: 20px;
      }
      .set.delegated .d {
        opacity: 0.32;
      }
      .d-auth.on {
        color: #d98420;
        opacity: 1;
      }
      .d-users.on {
        color: #2f6feb;
        opacity: 1;
      }
      .d-roles.on {
        color: var(--mk-signal);
        opacity: 1;
      }
    `,
  ],
})
export class AccessBadgesComponent {
  readonly access = input.required<AccessState>();

  protected readonly empty = computed(() => isEmpty(this.access()));

  protected readonly authTip = $localize`:@@Authenticated:Authenticated`;
  protected readonly delegatedTip = $localize`:@@Delegated_to_backend:No gateway rule — delegated to the API backend`;
  protected readonly usersTip = computed(() => {
    const u = this.access().users;
    return u.length ? $localize`:@@Users:Users` + ': ' + u.join(', ') : $localize`:@@Users:Users`;
  });
  protected readonly rolesTip = computed(() => {
    const r = this.access().roles;
    return r.length ? $localize`:@@Roles:Roles` + ': ' + r.join(', ') : $localize`:@@Roles:Roles`;
  });
}
