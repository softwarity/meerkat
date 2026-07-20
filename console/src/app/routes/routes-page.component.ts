import { Component, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatDialog } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { MatToolbarModule } from '@angular/material/toolbar';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import { RowActionsDirective } from '@softwarity/row-actions';
import { forkJoin } from 'rxjs';
import { ApiService, CatalogEntry, Route } from '../api.service';
import { RouteDialogComponent } from './route-dialog.component';

@Component({
  selector: 'app-routes-page',
  imports: [
    MatButtonModule,
    MatIconModule,
    MatTableModule,
    MatToolbarModule,
    LoadingIndicatorComponent,
    RowActionsDirective,
  ],
  styles: [
    `
      .banner {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 12px 24px;
      }
      .banner h1 {
        font-size: 1.15rem;
        font-weight: 500;
        margin: 0;
        flex: 1;
      }
      .content {
        padding: 0 24px 24px;
      }
      mat-cell,
      mat-header-cell {
        padding-right: 12px;
      }
      .muted {
        color: var(--mat-sys-on-surface-variant);
        font-size: 0.85em;
      }
      .off {
        opacity: 0.45;
      }
      .empty {
        padding: 48px;
        text-align: center;
        color: var(--mat-sys-on-surface-variant);
      }
    `,
  ],
  template: `
    <div class="banner">
      <h1>Gateway · Routes</h1>
      <button matIconButton (click)="load()" aria-label="Refresh">
        <mat-icon>refresh</mat-icon>
      </button>
      <button matButton="filled" (click)="edit(null)">
        <mat-icon>add</mat-icon>
        New route
      </button>
    </div>

    <div class="content">
      @if (loading()) {
        <loading-indicator withContainer />
      } @else if (routes().length === 0) {
        <div class="empty">No route yet — create the first one.</div>
      } @else {
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
                <button matIconButton (click)="edit(r)" aria-label="Edit">
                  <mat-icon>edit</mat-icon>
                </button>
                <button matIconButton (click)="remove(r)" aria-label="Delete">
                  <mat-icon>delete</mat-icon>
                </button>
              </span>
            </mat-cell>
          </ng-container>

          <mat-header-row *matHeaderRowDef="columns"></mat-header-row>
          <mat-row *matRowDef="let row; columns: columns"></mat-row>
        </mat-table>
      }
    </div>
  `,
})
export class RoutesPageComponent {
  private api = inject(ApiService);
  private dialog = inject(MatDialog);
  private snack = inject(MatSnackBar);

  protected readonly columns = ['order', 'name', 'matching', 'upstream', 'actions'];
  protected readonly loading = signal(true);
  protected readonly routes = signal<Route[]>([]);
  protected catalog: CatalogEntry[] = [];

  constructor() {
    this.load();
  }

  load(): void {
    this.loading.set(true);
    forkJoin({ catalog: this.api.catalog(), routes: this.api.listRoutes() }).subscribe({
      next: ({ catalog, routes }) => {
        this.catalog = catalog;
        this.routes.set(routes);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  summary(r: Route): string {
    const preds = r.predicates.map((p) => this.brickSummary(p.type, p.args)).join(' AND ');
    const filters = r.filters.length ? ` · ${r.filters.length} filter(s)` : '';
    return preds + filters;
  }

  private brickSummary(type: string, args?: Record<string, unknown>): string {
    const first = args ? Object.values(args)[0] : undefined;
    const value = Array.isArray(first) ? first.join(', ') : (first ?? '');
    return value === '' ? type : `${type}: ${value}`;
  }

  edit(route: Route | null): void {
    this.dialog
      .open(RouteDialogComponent, {
        width: '720px',
        maxWidth: '95vw',
        data: { route, catalog: this.catalog },
      })
      .afterClosed()
      .subscribe((saved) => {
        if (saved) {
          this.snack.open(`Route "${saved.name}" saved and applied`, undefined, { duration: 2500 });
          this.load();
        }
      });
  }

  remove(route: Route): void {
    if (!confirm(`Delete route "${route.name}"?`)) {
      return;
    }
    this.api.deleteRoute(route.id).subscribe({
      next: () => {
        this.snack.open(`Route "${route.name}" deleted`, undefined, { duration: 2500 });
        this.load();
      },
      error: () => this.snack.open('Delete failed', undefined, { duration: 3000 }),
    });
  }
}
