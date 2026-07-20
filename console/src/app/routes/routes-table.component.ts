import { Component, input, output } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatTableModule } from '@angular/material/table';
import { RowActionsDirective } from '@softwarity/row-actions';
import { Route } from '../api.service';

// Presentational routes table: data in, intents out.
@Component({
  selector: 'app-routes-table',
  imports: [MatButtonModule, MatIconModule, MatTableModule, RowActionsDirective],
  styles: [
    `
      .muted {
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.85em;
      }
      .off {
        opacity: 0.45;
      }
    `,
  ],
  template: `
    <mat-table [dataSource]="routes()">
      <ng-container matColumnDef="order">
        <mat-header-cell *matHeaderCellDef>#</mat-header-cell>
        <mat-cell *matCellDef="let r" [class.off]="!r.enabled">{{ r.order }}</mat-cell>
      </ng-container>

      <ng-container matColumnDef="name">
        <mat-header-cell *matHeaderCellDef>Name</mat-header-cell>
        <mat-cell *matCellDef="let r" [class.off]="!r.enabled">
          {{ r.name }}
          @if (r.authenticated) {
            <mat-icon inline title="authenticated">lock</mat-icon>
          }
        </mat-cell>
      </ng-container>

      <ng-container matColumnDef="matching">
        <mat-header-cell *matHeaderCellDef>Matching</mat-header-cell>
        <mat-cell *matCellDef="let r" [class.off]="!r.enabled">
          <span class="muted">{{ summary(r) }}</span>
        </mat-cell>
      </ng-container>

      <ng-container matColumnDef="upstream">
        <mat-header-cell *matHeaderCellDef>Upstream</mat-header-cell>
        <mat-cell *matCellDef="let r" [class.off]="!r.enabled">{{ r.upstream }}</mat-cell>
      </ng-container>

      <ng-container matColumnDef="actions">
        <mat-header-cell *matHeaderCellDef></mat-header-cell>
        <mat-cell *matCellDef="let r">
          <span rowActions>
            <button matIconButton (click)="edit.emit(r)" aria-label="Edit">
              <mat-icon>edit</mat-icon>
            </button>
            <button matIconButton (click)="remove.emit(r)" aria-label="Delete">
              <mat-icon>delete</mat-icon>
            </button>
          </span>
        </mat-cell>
      </ng-container>

      <mat-header-row *matHeaderRowDef="columns"></mat-header-row>
      <mat-row *matRowDef="let row; columns: columns"></mat-row>
    </mat-table>
  `,
})
export class RoutesTableComponent {
  readonly routes = input.required<Route[]>();
  readonly edit = output<Route>();
  readonly remove = output<Route>();

  protected readonly columns = ['order', 'name', 'matching', 'upstream', 'actions'];

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
