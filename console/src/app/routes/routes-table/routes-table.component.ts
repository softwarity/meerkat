import { CdkDragDrop, DragDropModule, moveItemInArray } from '@angular/cdk/drag-drop';
import { Component, input, output } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatTableModule } from '@angular/material/table';
import { MatTooltipModule } from '@angular/material/tooltip';
import { RowActionsDirective } from '@softwarity/row-actions';
import { Route } from '../../api.service';
import { AccessBadgesComponent } from '../endpoint-security/access-badges.component';
import { AccessState, emptyAccess } from '../endpoint-security/access-editor.component';

// Presentational routes table: data in, intents out. Rows are drag-orderable
// (first-match-wins, so order is significant) via the drag handle.
@Component({
  selector: 'app-routes-table',
  imports: [
    DragDropModule,
    MatButtonModule,
    MatIconModule,
    MatTableModule,
    MatTooltipModule,
    RowActionsDirective,
    AccessBadgesComponent,
  ],
  templateUrl: './routes-table.component.html',
  styleUrl: './routes-table.component.scss',
})
export class RoutesTableComponent {
  readonly routes = input.required<Route[]>();
  readonly edit = output<Route>();
  readonly remove = output<Route>();
  readonly toggleEnabled = output<Route>();
  // Emits the full ordered list of route ids after a drag.
  readonly reorder = output<string[]>();

  protected readonly columns = ['name', 'access', 'matching', 'upstream'];

  // Row-actions toolbars self-close on row click (closeOnClick, 3.1.0) —
  // nothing floats over the editor drawer this click opens.
  protected onRowClick(route: Route): void {
    this.edit.emit(route);
  }

  protected drop(event: CdkDragDrop<Route[]>): void {
    if (event.previousIndex === event.currentIndex) return;
    const ids = this.routes().map((r) => r.id);
    moveItemInArray(ids, event.previousIndex, event.currentIndex);
    this.reorder.emit(ids);
  }

  // The route's base Access as the badges' non-optional shape (level /
  // organisations / users / roles, same as the endpoint-security screen).
  protected accessBadge(r: Route): AccessState {
    const a = r.access;
    return a
      ? { level: a.level ?? '', tenants: a.tenants ?? [], roles: a.roles ?? [], users: a.users ?? [] }
      : emptyAccess();
  }

  // How many operations carry their own rule (RBAC-07). Passing it is what
  // lets the badges tell "delegated on the route, but gated per endpoint" from
  // "gated nowhere at all" - only the second is drawn as a warning.
  protected endpointRules(r: Route): number {
    return r.api?.security?.endpoints?.length ?? 0;
  }

  protected summary(r: Route): string {
    const preds = r.predicates
      .map((p) => {
        const first = p.args ? Object.values(p.args)[0] : undefined;
        const value = Array.isArray(first) ? first.join(', ') : (first ?? '');
        return value === '' ? p.type : `${p.type}: ${value}`;
      })
      .join(' AND ');
    return r.filters.length ? `${preds} · ${r.filters.length} filter(s)` : preds;
  }
}
