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
// server-side by capability (RBAC-05): root sees all, infra-admin the routing
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
  styleUrl: './audit-page.component.scss',
  templateUrl: './audit-page.component.html',
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
