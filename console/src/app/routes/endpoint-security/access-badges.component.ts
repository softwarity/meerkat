import { Component, computed, input } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { ACCESS_LEVELS, AccessState, isEmpty } from './access-editor.component';

// The rule at a glance. The LEVEL is written, not drawn: a lit padlock said
// "some rule" and left "signed in", "in an organisation" and "in one of these
// two" looking identical, which is the one thing a list of routes has to make
// obvious. So it is a short word - AUTH, ORG, ORG·2 - and only the two lists
// and the endpoint count stay as icons, where a number IS the information.
//
// The counts sit in a FIXED-WIDTH slot right of their icon, so a number
// appearing never shifts the row.
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
    <span class="set" [class.delegated]="empty()" [class.unguarded]="unguarded()">
      <span class="lvl" [class.on]="gated()" [matTooltip]="levelTip()">{{ levelShort() }}</span>
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
      // The level, written. Sized for its widest form so the icons after it
      // line up whatever the rule says.
      .lvl {
        display: inline-block;
        min-width: 5ch;
        text-align: center;
        padding: 1px 6px;
        border-radius: 999px;
        font-size: 0.68rem;
        font-weight: 700;
        letter-spacing: 0.04em;
        color: var(--mat-sys-on-surface-variant);
        border: 1px solid var(--mat-sys-outline-variant);
      }
      .lvl.on {
        color: #d98420;
        border-color: currentColor;
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
      .d-endpoints.on {
        color: #2f6feb;
        opacity: 1;
      }
      // Nothing gated anywhere: the only state this row raises its voice for.
      .set.unguarded .d,
      .set.unguarded .lvl {
        color: var(--mat-sys-error);
        opacity: 0.85;
      }
      .set.unguarded .lvl {
        border-color: currentColor;
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
  protected readonly gated = computed(() => this.access().level !== '');
  // The written form. Kept to a few characters because it sits in a table
  // column: the full sentence is one hover away, and the organisations it
  // names come with it rather than needing a second badge.
  protected readonly levelShort = computed(() => {
    const a = this.access();
    switch (a.level) {
      case 'auth':
        return $localize`:@@Level_short_auth:AUTH`;
      case 'tenant':
        return $localize`:@@Level_short_tenant:ORG`;
      case 'tenants':
        return $localize`:@@Level_short_tenants:ORG` + '\u00b7' + a.tenants.length;
      default:
        return '\u2014';
    }
  });
  // The full sentence on hover, carried by the level chip alone - the set used
  // to hold one too, and every icon then answered twice. The organisations
  // themselves are not listed: the rule carries ids, which say nothing to a
  // reader, and the route's own screen shows them by name.
  protected readonly levelTip = computed(() => {
    if (this.unguarded()) return this.unguardedTip;
    if (this.empty()) return this.delegatedTip;
    return ACCESS_LEVELS.find((l) => l.value === this.access().level)?.label ?? '';
  });
  protected readonly delegatedTip = $localize`:@@Delegated_to_backend:No gateway rule — delegated to the API backend`;
  protected readonly unguardedTip = $localize`:@@Nothing_gated_here:Meerkat gates nothing here, on the route or on any endpoint: the service decides alone.`;
  protected readonly endpointsTip = computed(() => {
    const n = this.endpoints() ?? 0;
    return n
      ? $localize`:@@Endpoints_with_their_own_rule:Endpoints with their own rule` + ': ' + n
      : $localize`:@@Every_endpoint_follows_the_route:Every endpoint follows the route's rule`;
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
