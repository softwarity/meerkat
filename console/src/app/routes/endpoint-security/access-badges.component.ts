import { Component, computed, input } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { ACCESS_LEVELS, AccessState, isEmpty } from './access-editor.component';

// The rule at a glance: the belonging level, then the two lists. Every icon is
// always present and lights up when its dimension is set, so the row never
// shifts; the counts sit in a FIXED-WIDTH slot right of their icon. All dim
// means no gateway rule at all - delegated to the upstream, which is NOT the
// same as public and is why the lock has three states rather than two.
@Component({
  selector: 'app-access-badges',
  imports: [MatIconModule, MatTooltipModule],
  template: `
    <span class="set" [class.delegated]="empty()" [matTooltip]="empty() ? delegatedTip : ''">
      <mat-icon class="d d-auth" [class.on]="gated()" [matTooltip]="levelTip()">{{ levelIcon() }}</mat-icon>
      <span class="d d-tenants" [class.on]="access().level === 'tenant' || access().level === 'tenants'" [matTooltip]="tenantsTip()">
        <mat-icon>corporate_fare</mat-icon><span class="n">{{ access().tenants.length || '' }}</span>
      </span>
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
      .d-tenants.on {
        color: var(--mk-signal);
        opacity: 1;
      }
    `,
  ],
})
export class AccessBadgesComponent {
  readonly access = input.required<AccessState>();

  protected readonly empty = computed(() => isEmpty(this.access()));
  protected readonly gated = computed(() => this.access().level !== '' && this.access().level !== 'public');

  // An OPEN lock for public: the gateway decided, and it decided to open. A
  // dim closed lock is the delegated case - no decision at all.
  protected readonly levelIcon = computed(() => (this.access().level === 'public' ? 'lock_open' : 'lock'));
  protected readonly levelTip = computed(
    () => ACCESS_LEVELS.find((l) => l.value === this.access().level)?.label ?? '',
  );
  protected readonly tenantsTip = computed(() => {
    const a = this.access();
    if (a.level === 'tenants') {
      return $localize`:@@Organisations:Organisations` + ': ' + a.tenants.join(', ');
    }
    return ACCESS_LEVELS.find((l) => l.value === a.level)?.label ?? '';
  });
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
