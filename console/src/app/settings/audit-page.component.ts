import { Component, computed, inject, LOCALE_ID, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import { DateTime } from 'luxon';
import { ApiService, AuditChange, AuditEvent } from '../api.service';

// The audit trail (phase 2): who changed what, with the exact field-level diff.
// Its own transverse section (not under Application). Read-only and scoped
// server-side by capability (RBAC-05): root sees all, gateway-admin the routing
// plane, app-admin the identity, a tenant admin their tenants. Target + period
// filter on the server; a free-text box narrows the loaded page.
@Component({
  selector: 'app-audit-page',
  imports: [
    MatButtonModule,
    MatCardModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatSelectModule,
    LoadingIndicatorComponent,
  ],
  styles: [
    `
      /* A fixed banner + filters, then a scrollable event list — the header and
         filters stay visible however long the trail is. */
      :host {
        display: flex;
        flex-direction: column;
        height: 100%;
        min-height: 0;
      }
      .banner {
        display: flex;
        align-items: center;
        gap: 16px;
        padding: 12px 24px;
        flex: none;
      }
      .banner h1 {
        font-size: 1.15rem;
        font-weight: 500;
        margin: 0;
        flex: 1;
      }
      .toolbar {
        flex: none;
        padding: 0 24px 12px;
        display: grid;
        gap: 12px;
        max-width: 960px;
      }
      .scroll {
        flex: 1 1 auto;
        min-height: 0;
        overflow-y: auto;
        padding: 4px 24px 24px;
      }
      .filters {
        display: flex;
        gap: 12px;
        flex-wrap: wrap;
        align-items: center;
      }
      .filters .grow {
        flex: 1 1 220px;
      }
      .short {
        width: 170px;
      }
      .events {
        display: grid;
        gap: 8px;
        max-width: 960px;
      }
      .event {
        display: grid;
        grid-template-columns: 150px 1fr;
        gap: 4px 16px;
        padding: 12px 16px;
        border: 1px solid var(--mat-sys-outline-variant);
        border-radius: 10px;
        position: relative;
        overflow: hidden;
      }
      /* The mint accent the other list panels wear. */
      .event::before {
        content: '';
        position: absolute;
        inset: 0 0 auto 0;
        height: 3px;
        background: var(--mat-sys-primary);
        opacity: 0.7;
      }
      .when {
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.8rem;
        padding-top: 2px;
      }
      .head {
        display: flex;
        align-items: baseline;
        gap: 8px;
        flex-wrap: wrap;
      }
      .action {
        font-family: monospace;
        font-weight: 600;
      }
      .who {
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.85rem;
      }
      .target {
        font-size: 0.85rem;
      }
      .target .kind {
        font-family: monospace;
        color: var(--mat-sys-on-surface-variant);
      }
      .changes {
        grid-column: 2;
        display: grid;
        gap: 3px;
        margin-top: 4px;
      }
      .change {
        font-size: 0.85rem;
        display: flex;
        gap: 6px;
        align-items: baseline;
        flex-wrap: wrap;
      }
      .change .field {
        font-family: monospace;
        color: var(--mat-sys-primary);
      }
      .change .from {
        color: var(--mat-sys-error);
        text-decoration: line-through;
        opacity: 0.8;
      }
      .change .to {
        color: var(--mat-sys-on-surface);
        font-weight: 500;
      }
      .change .arrow {
        color: var(--mat-sys-on-surface-variant);
      }
      .detail {
        grid-column: 2;
        font-size: 0.85rem;
        color: var(--mat-sys-on-surface-variant);
        font-style: italic;
      }
      .empty {
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.9rem;
        padding: 24px 0;
        text-align: center;
      }
    `,
  ],
  template: `
    <div class="banner">
      <h1 i18n="@@Audit">Audit</h1>
      <button matIconButton (click)="reload()" i18n-matTooltip="@@Refresh" matTooltip="Refresh">
        <mat-icon>refresh</mat-icon>
      </button>
    </div>

    <div class="toolbar">
      <p class="hint" i18n="@@Audit_hint">
        Every administrative change, with the exact fields that moved and their before and after.
      </p>

      <div class="filters">
        <mat-form-field class="short" subscriptSizing="dynamic">
          <mat-label i18n="@@Target">Target</mat-label>
          <mat-select [value]="target()" (selectionChange)="target.set($event.value); reload()">
            <mat-option value="" i18n="@@All">All</mat-option>
            @for (k of targets; track k) {
              <mat-option [value]="k">{{ k }}</mat-option>
            }
          </mat-select>
        </mat-form-field>

        <mat-form-field class="short" subscriptSizing="dynamic">
          <mat-label i18n="@@Period">Period</mat-label>
          <mat-select [value]="period()" (selectionChange)="period.set($event.value); reload()">
            <mat-option [value]="1" i18n="@@Last_24h">Last 24 hours</mat-option>
            <mat-option [value]="7" i18n="@@Last_7_days">Last 7 days</mat-option>
            <mat-option [value]="30" i18n="@@Last_30_days">Last 30 days</mat-option>
            <mat-option [value]="0" i18n="@@All_time">All time</mat-option>
          </mat-select>
        </mat-form-field>

        <mat-form-field class="grow" subscriptSizing="dynamic">
          <mat-label i18n="@@Search">Search</mat-label>
          <input matInput [value]="search()" (input)="search.set($any($event.target).value)" />
        </mat-form-field>
      </div>
    </div>

    <div class="scroll">
      @if (loading()) {
        <loading-indicator withContainer />
      } @else {
        <div class="events">
          @for (e of filtered(); track e.id) {
            <div class="event">
              <div class="when" [title]="fullWhen(e.at)">{{ relWhen(e.at) }}</div>
              <div>
                <div class="head">
                  <span class="action">{{ e.action }}</span>
                  <span class="who">
                    <ng-container i18n="@@by">by</ng-container> {{ e.actorName || e.actorId || '?' }}
                  </span>
                </div>
                @if (e.targetName || e.targetId) {
                  <div class="target">
                    <span class="kind">{{ e.target }}</span> {{ e.targetName || e.targetId }}
                  </div>
                }
                @if (e.changes?.length) {
                  <div class="changes">
                    @for (c of e.changes; track c.field) {
                      <div class="change">
                        <span class="field">{{ c.field }}</span>
                        <span class="from">{{ fmt(c.from) }}</span>
                        <span class="arrow">&#8594;</span>
                        <span class="to">{{ fmt(c.to) }}</span>
                      </div>
                    }
                  </div>
                } @else if (e.detail) {
                  <div class="detail">{{ e.detail }}</div>
                }
              </div>
            </div>
          } @empty {
            <p class="empty" i18n="@@No_audit_events">No audit events for this filter.</p>
          }
        </div>
      }
    </div>
  `,
})
export class AuditPageComponent {
  private readonly api = inject(ApiService);
  private readonly locale = inject(LOCALE_ID);

  // The known target kinds (mirrors the server's taxonomy).
  protected readonly targets = ['tenant', 'user', 'membership', 'group', 'role', 'settings', 'route', 'theme'];

  protected readonly loading = signal(true);
  protected readonly events = signal<AuditEvent[]>([]);
  protected readonly target = signal('');
  protected readonly period = signal(7); // days; 0 = all time
  protected readonly search = signal('');

  protected readonly filtered = computed(() => {
    const q = this.search().trim().toLowerCase();
    if (!q) return this.events();
    return this.events().filter((e) =>
      [e.action, e.actorName, e.actorId, e.target, e.targetName]
        .some((v) => (v ?? '').toLowerCase().includes(q)),
    );
  });

  constructor() {
    this.reload();
  }

  protected reload(): void {
    this.loading.set(true);
    const days = this.period();
    const since = days > 0 ? Math.floor(Date.now() / 1000) - days * 86400 : undefined;
    this.api.listAudit({ target: this.target() || undefined, since, limit: 500 }).subscribe({
      next: (events) => {
        this.events.set(events);
        this.loading.set(false);
      },
      error: () => {
        this.events.set([]);
        this.loading.set(false);
      },
    });
  }

  protected relWhen(at: number): string {
    return DateTime.fromSeconds(at).reconfigure({ locale: this.locale }).toRelative() ?? '';
  }

  protected fullWhen(at: number): string {
    return DateTime.fromSeconds(at).reconfigure({ locale: this.locale }).toLocaleString(DateTime.DATETIME_MED);
  }

  // A change value as a short readable string: empty/absent shows a placeholder,
  // objects/arrays as compact JSON, everything else as-is.
  protected fmt(v: AuditChange['from']): string {
    if (v === undefined || v === null || v === '') return '∅';
    if (typeof v === 'object') return JSON.stringify(v);
    return String(v);
  }
}
