import { Component, computed, inject, signal } from '@angular/core';
import { MAT_DIALOG_DATA, MatDialogModule } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatMenuModule } from '@angular/material/menu';
import { MatSelectModule } from '@angular/material/select';
import { MatTooltipModule } from '@angular/material/tooltip';
import { ApiService, Route, RouteProbeRequest, RouteProbeResult, RouteProbeStep } from '../api.service';
import { FormFieldComponent } from '../shared/form-field.component';
import { humanize } from './predicates/args';

// Route probe (ROUTE-15): compose a fictional request criterion by criterion,
// press play, and see which route of the LIVE snapshot takes it: the whole
// traversal, in first-match-wins order, with the predicates that refused.
// The route list shows from the start; play fills the verdicts in. Matching
// only: no upstream is ever contacted. Reached from the Routes page.

export interface RouteProbeDialogData {
  routes: Route[];
}

// One display row: a route of the page's list, annotated with its probe step
// once a probe ran (a disabled route never gets one: it is not in the live
// snapshot).
interface ProbeRow {
  id: string;
  name: string;
  enabled: boolean;
  step: RouteProbeStep | null;
  win: boolean;
  after: boolean;
}

// A criterion mirrors one thing a predicate can look at. `name` is only used
// by the named kinds (header, cookie, query).
type CriterionKind = 'host' | 'header' | 'cookie' | 'query' | 'remote-addr' | 'at' | 'lottery';

interface Criterion {
  kind: CriterionKind;
  name: string;
  value: string;
}

// Only the named kinds make sense several times (two different headers...);
// the request has a single host, address, clock and draw.
const MULTI_INSTANCE: CriterionKind[] = ['header', 'cookie', 'query'];

@Component({
  selector: 'app-route-probe-dialog',
  imports: [
    MatButtonModule,
    MatDialogModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatMenuModule,
    MatSelectModule,
    MatTooltipModule,
    FormFieldComponent,
  ],
  styleUrl: './route-probe-dialog.component.scss',
  templateUrl: './route-probe-dialog.component.html',
})
export class RouteProbeDialogComponent {
  private readonly api = inject(ApiService);
  private readonly input = inject<RouteProbeDialogData>(MAT_DIALOG_DATA);

  protected readonly METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
  protected readonly KINDS: CriterionKind[] = [
    'host',
    'header',
    'cookie',
    'query',
    'remote-addr',
    'at',
    'lottery',
  ];

  protected readonly method = signal('GET');
  protected readonly path = signal('/');
  protected readonly criteria = signal<Criterion[]>([]);

  protected readonly running = signal(false);
  protected readonly error = signal('');
  protected readonly result = signal<RouteProbeResult | null>(null);

  // The page's routes, in order, annotated with the probe verdicts once one
  // ran. Rows below the winner are dimmed (in production the matcher stops
  // there, first match wins).
  protected readonly rows = computed<ProbeRow[]>(() => {
    const res = this.result();
    const steps = new Map((res?.steps ?? []).map((s) => [s.routeId, s]));
    let winnerSeen = false;
    return this.input.routes.map((r) => {
      const win = !!res && r.id === res.winnerId;
      const after = !!res?.winnerId && winnerSeen && !win;
      if (win) winnerSeen = true;
      return { id: r.id, name: r.name, enabled: r.enabled, step: steps.get(r.id) ?? null, win, after };
    });
  });

  protected mark(row: ProbeRow): string {
    if (!row.enabled) return 'block';
    if (!row.step) return 'radio_button_unchecked';
    return row.step.matched ? 'check' : 'close';
  }

  protected named(kind: CriterionKind): boolean {
    return MULTI_INSTANCE.includes(kind);
  }

  // Single-instance kinds gray out once present.
  protected taken(kind: CriterionKind): boolean {
    return !MULTI_INSTANCE.includes(kind) && this.criteria().some((c) => c.kind === kind);
  }

  protected kindLabel(kind: CriterionKind): string {
    switch (kind) {
      case 'host':
        return $localize`:@@Host:Host`;
      case 'header':
        return $localize`:@@Header:Header`;
      case 'cookie':
        return $localize`:@@Cookie:Cookie`;
      case 'query':
        return $localize`:@@Query_param:Query parameter`;
      case 'remote-addr':
        return $localize`:@@Client_address:Client address`;
      case 'at':
        return $localize`:@@Date_and_time:Date and time`;
      case 'lottery':
        return $localize`:@@Canary_draw:Canary draw`;
    }
  }

  protected placeholderFor(kind: CriterionKind): string {
    switch (kind) {
      case 'host':
        return 'app.example.com';
      case 'remote-addr':
        return '203.0.113.7';
      default:
        return '';
    }
  }

  protected add(kind: CriterionKind): void {
    this.criteria.update((list) => [...list, { kind, name: '', value: kind === 'lottery' ? '0.5' : '' }]);
  }

  protected patch(index: number, part: Partial<Criterion>): void {
    this.criteria.update((list) => list.map((c, i) => (i === index ? { ...c, ...part } : c)));
  }

  protected removeAt(index: number): void {
    this.criteria.update((list) => list.filter((_, i) => i !== index));
  }

  // The predicates that refused this route, as a readable list.
  protected failed(step: RouteProbeStep): string {
    return step.predicates
      .filter((p) => !p.matched)
      .map((p) => humanize(p.type))
      .join(', ');
  }

  // Tooltip detail: the refusing predicates with their arguments.
  protected failedDetail(step: RouteProbeStep): string {
    return step.predicates
      .filter((p) => !p.matched)
      .map((p) => p.type + (p.args ? ' ' + JSON.stringify(p.args) : ''))
      .join('\n');
  }

  protected play(): void {
    const req: RouteProbeRequest = { method: this.method(), path: this.path().trim() || '/' };
    for (const c of this.criteria()) {
      const value = c.value.trim();
      const name = c.name.trim();
      switch (c.kind) {
        case 'host':
          if (value) req.host = value;
          break;
        case 'header':
          if (name) req.headers = { ...(req.headers ?? {}), [name]: value };
          break;
        case 'cookie':
          if (name) req.cookies = { ...(req.cookies ?? {}), [name]: value };
          break;
        case 'query':
          if (name) req.query = { ...(req.query ?? {}), [name]: value };
          break;
        case 'remote-addr':
          // The matcher expects ip:port; a bare IPv4 gets a harmless port.
          if (value) req.remoteAddr = value.includes(':') ? value : value + ':54321';
          break;
        case 'at': {
          const at = new Date(value);
          if (value && !isNaN(+at)) req.at = at.toISOString();
          break;
        }
        case 'lottery': {
          const draw = Number(value);
          if (value && isFinite(draw)) req.lottery = Math.min(Math.max(draw, 0), 0.999);
          break;
        }
      }
    }
    this.running.set(true);
    this.error.set('');
    this.api.probeRoutes(req).subscribe({
      next: (r) => {
        this.result.set(r);
        this.running.set(false);
      },
      error: (err: unknown) => {
        const e = err as { error?: { error?: string } };
        this.error.set(
          typeof e?.error?.error === 'string' ? e.error.error : $localize`:@@Request_failed:Request failed`,
        );
        this.running.set(false);
      },
    });
  }
}
