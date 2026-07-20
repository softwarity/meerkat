import { Component, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatDialog } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';
import { MatSnackBar } from '@angular/material/snack-bar';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import { forkJoin } from 'rxjs';
import { ApiService, CatalogEntry, Route } from '../api.service';
import { RouteDialogComponent } from './route-dialog.component';
import { RoutesTableComponent } from './routes-table.component';

@Component({
  selector: 'app-routes-page',
  imports: [MatButtonModule, MatIconModule, LoadingIndicatorComponent, RoutesTableComponent],
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
      .empty {
        padding: 48px;
        text-align: center;
        color: var(--mat-sys-on-surface-variant);
      }
    `,
  ],
  template: `
    <div class="banner">
      <h1 i18n="@@Gateway_Routes">Gateway · Routes</h1>
      <button matIconButton (click)="load()" i18n-aria-label="@@Refresh" aria-label="Refresh">
        <mat-icon>refresh</mat-icon>
      </button>
      <button matButton="filled" (click)="edit(null)">
        <mat-icon>add</mat-icon>
        <ng-container i18n="@@New_route">New route</ng-container>
      </button>
    </div>

    <div class="content">
      @if (loading()) {
        <loading-indicator withContainer />
      } @else if (routes().length === 0) {
        <div class="empty" i18n="@@No_route_yet_create_the_first_one">No route yet — create the first one.</div>
      } @else {
        <app-routes-table [routes]="routes()" (edit)="edit($event)" (remove)="remove($event)" />
      }
    </div>
  `,
})
export class RoutesPageComponent {
  private readonly api = inject(ApiService);
  private readonly dialog = inject(MatDialog);
  private readonly snack = inject(MatSnackBar);

  protected readonly loading = signal(true);
  protected readonly routes = signal<Route[]>([]);
  protected readonly catalog = signal<CatalogEntry[]>([]);

  constructor() {
    this.load();
  }

  load(): void {
    this.loading.set(true);
    forkJoin({ catalog: this.api.catalog(), routes: this.api.listRoutes() }).subscribe({
      next: ({ catalog, routes }) => {
        this.catalog.set(catalog);
        this.routes.set(routes);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  edit(route: Route | null): void {
    this.dialog
      .open(RouteDialogComponent, {
        width: '720px',
        maxWidth: '95vw',
        data: { route, catalog: this.catalog() },
      })
      .afterClosed()
      .subscribe((saved?: Route) => {
        if (saved) {
          this.snack.open($localize`:@@Route_NAME_saved_and_applied:Route "${saved.name}:NAME:" saved and applied`, undefined, { duration: 2500 });
          this.load();
        }
      });
  }

  remove(route: Route): void {
    if (!confirm($localize`:@@Delete_route_NAME:Delete route "${route.name}:NAME:"?`)) {
      return;
    }
    this.api.deleteRoute(route.id).subscribe({
      next: () => {
        this.snack.open($localize`:@@Route_NAME_deleted:Route "${route.name}:NAME:" deleted`, undefined, { duration: 2500 });
        this.load();
      },
      error: () => this.snack.open($localize`:@@Delete_failed:Delete failed`, undefined, { duration: 3000 }),
    });
  }
}
