import { Component, computed, inject, signal } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatSidenavModule } from '@angular/material/sidenav';
import { MatSnackBar } from '@angular/material/snack-bar';
import { ActivatedRoute, Router } from '@angular/router';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import { forkJoin } from 'rxjs';
import { ApiService, CatalogEntry, Route } from '../../api.service';
import { DialogsService } from '../../shared/dialogs.service';
import { RouteEditorComponent } from '../route-editor/route-editor.component';
import { RoutesTableComponent } from '../routes-table/routes-table.component';

@Component({
  selector: 'app-routes-page',
  imports: [
    MatButtonModule,
    MatIconModule,
    MatSidenavModule,
    LoadingIndicatorComponent,
    RoutesTableComponent,
    RouteEditorComponent,
  ],
  templateUrl: './routes-page.component.html',
  styleUrl: './routes-page.component.scss',
})
export class RoutesPageComponent {
  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);
  private readonly dialogs = inject(DialogsService);
  private readonly router = inject(Router);
  private readonly ar = inject(ActivatedRoute);

  protected readonly loading = signal(true);
  protected readonly routes = signal<Route[]>([]);
  protected readonly catalog = signal<CatalogEntry[]>([]);

  // The URL drives the drawer (F5-proof): /routes/new = creating,
  // /routes/:id/:section = editing that route on that section.
  private readonly params = toSignal(this.ar.paramMap);
  private readonly urlSegs = toSignal(this.ar.url);
  protected readonly editing = computed<Route | 'new' | null>(() => {
    if (this.urlSegs()?.some((s) => s.path === 'new')) return 'new';
    const id = this.params()?.get('id');
    if (!id) return null;
    return this.routes().find((r) => r.id === id) ?? null;
  });
  protected readonly editingRoute = computed(() => {
    const e = this.editing();
    return e === null || e === 'new' ? null : e;
  });
  protected readonly section = computed(() => this.params()?.get('section') ?? 'general');

  constructor() {
    this.load();
  }

  protected openEdit(route: Route): void {
    void this.router.navigate(['/routes', route.id, 'general']);
  }

  protected openNew(): void {
    void this.router.navigate(['/routes', 'new']);
  }

  protected closeEditor(): void {
    if (this.editing() !== null) void this.router.navigate(['/routes']);
  }

  protected changeSection(s: string): void {
    const e = this.editing();
    if (e && e !== 'new') void this.router.navigate(['/routes', e.id, s]);
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

  // Save keeps the drawer OPEN: the URL stays (or gains the fresh id after a
  // creation), the reloaded list rebinds the fresh route into the editor.
  onSaved(saved: Route): void {
    this.snack.open($localize`:@@Route_NAME_saved_and_applied:Route "${saved.name}:NAME:" saved and applied`, undefined, { duration: 2500 });
    if (this.editing() === 'new') {
      void this.router.navigate(['/routes', saved.id, 'general'], { replaceUrl: true });
    }
    this.load();
  }

  // Persist a drag-reorder: apply optimistically, then save (order is
  // significant — first-match-wins). On failure, reload server truth.
  onReorder(ids: string[]): void {
    const byId = new Map(this.routes().map((r) => [r.id, r]));
    this.routes.set(ids.map((id) => byId.get(id)!).filter(Boolean));
    this.api.reorderRoutes(ids).subscribe({
      error: () => {
        this.snack.open($localize`:@@Request_failed:Request failed`, undefined, { duration: 3000 });
        this.load();
      },
    });
  }

  toggleEnabled(route: Route): void {
    this.api.putRoute({ ...route, enabled: !route.enabled }).subscribe({
      next: (saved) => {
        this.snack.open(
          saved.enabled
            ? $localize`:@@Route_NAME_enabled:Route "${saved.name}:NAME:" enabled`
            : $localize`:@@Route_NAME_disabled:Route "${saved.name}:NAME:" disabled`,
          undefined,
          { duration: 2500 },
        );
        this.load();
      },
      error: () => this.snack.open($localize`:@@Request_failed:Request failed`, undefined, { duration: 3000 }),
    });
  }

  async remove(route: Route): Promise<void> {
    const ok = await this.dialogs.confirm({
      title: $localize`:@@Delete_route_NAME:Delete route "${route.name}:NAME:"?`,
      confirmLabel: $localize`:@@Delete:Delete`,
      danger: true,
    });
    if (!ok) return;
    this.api.deleteRoute(route.id).subscribe({
      next: () => {
        this.snack.open($localize`:@@Route_NAME_deleted:Route "${route.name}:NAME:" deleted`, undefined, { duration: 2500 });
        this.load();
      },
      error: () => this.snack.open($localize`:@@Delete_failed:Delete failed`, undefined, { duration: 3000 }),
    });
  }
}
