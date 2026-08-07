import { Component, computed, input } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { ACCESS_LEVELS, AccessState, isEmpty } from './access-editor.component';

// The rule at a glance: the belonging level, the organisations, the two lists,
// and - when the caller passes it - the number of per-endpoint overrides. Every
// icon is always present and lights up when its dimension is set, so the row
// never shifts; the counts sit in a FIXED-WIDTH slot right of their icon.
//
// `unguarded` is the one thing drawn in the error tone: Meerkat poses NO
// condition here and none on any endpoint either. That is a legitimate choice -
// the service decides on its own - but on a list of forty routes it is the one
// state worth spotting without reading, because it is also what an unfinished
// route looks like.
@Component({
  selector: 'app-access-badges',
  imports: [MatIconModule, MatTooltipModule],
  template: `
    <span class="set" [class.delegated]="empty()" [class.unguarded]="unguarded()" [matTooltip]="setTip()">
      <span class="d d-auth" [class.on]="gated()" [matTooltip]="levelTip()">
        <mat-icon>lock</mat-icon><span class="n"></span>
      </span>
      <span class="d d-tenants" [class.on]="access().level === 'tenant' || access().level === 'tenants'" [matTooltip]="tenantsTip()">
        <mat-icon>corporate_fare</mat-icon><span class="n">{{ access().tenants.length || '' }}</span>
      </span>
      <span class="d d-users" [class.on]="access().users.length > 0" [matTooltip]="usersTip()">
        <mat-icon>group</mat-icon><span class="n">{{ access().users.length || '' }}</span>
      </span>
      <span class="d d-roles" [class.on]="access().roles.length > 0" [matTooltip]="rolesTip()">
        <mat-icon>badge</mat-icon><span class="n">{{ access().roles.length || '' }}</span>
      </span>
      @if (endpoints() !== null) {
        <span class="d d-endpoints" [class.on]="(endpoints() ?? 0) > 0" [matTooltip]="endpointsTip()">
          <mat-icon>api</mat-icon><span class="n">{{ endpoints() || '' }}</span>
        </span>
      }
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
      // Every dimension reserves the same count slot, the level included even
      // though it never has a number: without it the icons that DO carry a
      // count trail two characters of nothing and the row reads unevenly
      // spaced.
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
      .d-endpoints.on {
        color: #2f6feb;
        opacity: 1;
      }
      // Nothing gated anywhere: the only state this row raises its voice for.
      .set.unguarded .d {
        color: var(--mat-sys-error);
        opacity: 0.85;
      }
    `,
  ],
})
export class AccessBadgesComponent {
  readonly access = input.required<AccessState>();
  // The number of per-endpoint overrides (RBAC-07). null - the default - means
  // the caller is showing ONE rule and the question does not arise: inside the
  // endpoint screen, an operation with no override inherits the route's rule,
  // it is not unguarded.
  readonly endpoints = input<number | null>(null);

  protected readonly empty = computed(() => isEmpty(this.access()));
  protected readonly unguarded = computed(() => this.empty() && this.endpoints() === 0);
  protected readonly setTip = computed(() => {
    if (this.unguarded()) return this.unguardedTip;
    return this.empty() ? this.delegatedTip : '';
  });
  protected readonly gated = computed(() => this.access().level !== '');
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
  protected readonly unguardedTip = $localize`:@@Nothing_gated_here:Meerkat gates nothing here, on the route or on any endpoint: the service decides alone.`;
  protected readonly endpointsTip = computed(() => {
    const n = this.endpoints() ?? 0;
    return n
      ? $localize`:@@Endpoints_with_their_own_rule:Endpoints with their own rule` + ': ' + n
      : $localize`:@@No_endpoint_override:No endpoint overrides the route's rule`;
  });
  protected readonly usersTip = computed(() => {
    const u = this.access().users;
    return u.length ? $localize`:@@Users:Users` + ': ' + u.join(', ') : $localize`:@@Users:Users`;
  });
  protected readonly rolesTip = computed(() => {
    const r = this.access().roles;
    return r.length ? $localize`:@@Roles:Roles` + ': ' + r.join(', ') : $localize`:@@Roles:Roles`;
  });
}
