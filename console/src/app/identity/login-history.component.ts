import { DatePipe } from '@angular/common';
import { Component, effect, inject, input, signal, untracked } from '@angular/core';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import { catchError, of } from 'rxjs';
import { ApiService, LoginEvent } from '../api.service';

// A user's sign-in history, read-only: the same data the user sees on
// /profile/history. Loads itself - with a tenantId the tenant-scoped endpoint
// answers (OWNER/ADMIN), otherwise the root one.
@Component({
  selector: 'app-login-history',
  imports: [DatePipe, LoadingIndicatorComponent],
  styles: [
    `
      :host {
        display: block;
      }
      .row {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 8px 0;
      }
      .row + .row {
        border-top: 1px solid var(--mat-sys-outline-variant);
      }
      .lines {
        flex: 1;
        min-width: 0;
        display: grid;
        gap: 2px;
      }
      .label {
        font-size: 0.9rem;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .meta {
        font-size: 0.72rem;
        color: var(--mat-sys-on-surface-variant);
      }
      .method {
        font-size: 0.62rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        border: 1px solid var(--mat-sys-outline-variant);
        border-radius: 999px;
        padding: 2px 8px;
        color: var(--mat-sys-on-surface-variant);
        white-space: nowrap;
      }
      .when {
        font-size: 0.75rem;
        color: var(--mat-sys-on-surface-variant);
        white-space: nowrap;
      }
      .empty {
        margin: 0;
        padding: 8px 0;
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.85rem;
      }
    `,
  ],
  template: `
    @if (events(); as list) {
      @for (e of list; track e.id) {
        <div class="row">
          <div class="lines">
            <span class="label">{{ e.label }}</span>
            @if (e.ip || e.country) {
              <span class="meta">{{ e.ip }}{{ e.country ? ' - ' + e.country : '' }}</span>
            }
          </div>
          <span class="method">{{ methodLabel(e.method) }}</span>
          <span class="when">{{ e.at * 1000 | date: 'yyyy-MM-dd HH:mm' }}</span>
        </div>
      } @empty {
        <p class="empty" i18n="@@No_sign_in_recorded_yet">No sign-in recorded yet.</p>
      }
    } @else {
      <loading-indicator />
    }
  `,
})
export class LoginHistoryComponent {
  readonly userId = input.required<string>();
  readonly tenantId = input('');

  private readonly api = inject(ApiService);
  protected readonly events = signal<LoginEvent[] | null>(null);

  constructor() {
    effect(() => {
      const userId = this.userId();
      const tenantId = this.tenantId();
      untracked(() => this.load(userId, tenantId));
    });
  }

  private load(userId: string, tenantId: string): void {
    this.events.set(null);
    (tenantId ? this.api.memberLogins(tenantId, userId) : this.api.userLogins(userId))
      .pipe(catchError(() => of<LoginEvent[]>([])))
      .subscribe((list) => this.events.set(list));
  }

  protected methodLabel(method: string): string {
    switch (method) {
      case 'passkey':
        return $localize`:@@method_passkey:passkey`;
      case 'totp':
        return $localize`:@@method_password_code:password + code`;
      default:
        return $localize`:@@method_password:password`;
    }
  }
}
