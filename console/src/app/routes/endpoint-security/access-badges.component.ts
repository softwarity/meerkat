import { Component, computed, input } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { AccessState, isEmpty } from './access-editor.component';

// The three access dimensions shown at a glance: authentication, named users,
// named roles. Each icon is always present and lights up when its dimension is
// set; the users/roles counts sit in a FIXED-WIDTH slot (two digits) right of
// the icon, so a count is always visible yet never shifts the layout. All three
// dim means no gateway rule (delegated to the API backend).
@Component({
  selector: 'app-access-badges',
  imports: [MatIconModule, MatTooltipModule],
  template: `
    <span class="set" [class.delegated]="empty()" [matTooltip]="empty() ? delegatedTip : ''">
      <mat-icon class="d d-auth" [class.on]="access().authenticated" [matTooltip]="authTip">lock</mat-icon>
      <span class="d d-users" [class.on]="access().users.length > 0" [matTooltip]="usersTip()">
        <mat-icon>group</mat-icon><span class="n">{{ access().users.length || '' }}</span>
      </span>
      <span class="d d-roles" [class.on]="access().roles.length > 0" [matTooltip]="rolesTip()">
        <mat-icon>badge</mat-icon><span class="n">{{ access().roles.length || '' }}</span>
      </span>
    </span>
  `,
  styles: [
    `
      .set {
        display: inline-flex;
        align-items: center;
        gap: 10px;
      }
      .d {
        display: inline-flex;
        align-items: center;
        color: var(--mat-sys-outline);
        opacity: 0.5;
      }
      .d mat-icon {
        font-size: 20px;
        width: 20px;
        height: 20px;
      }
      .n {
        display: inline-block;
        width: 2ch;
        text-align: left;
        margin-left: 2px;
        font-size: 0.7rem;
        font-weight: 700;
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
