import { Component, computed, effect, inject, input, signal } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatSnackBar } from '@angular/material/snack-bar';
import { NavigationEnd, Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { LoadingIndicatorComponent } from '@softwarity/loading-indicator';
import { filter, map } from 'rxjs';
import { ApiService } from '../../api.service';
import { FormFieldComponent } from '../../shared/form-field.component';
import { TenantScope } from '../tenant-scope';

// One tenant's administration — a routed LAYOUT: every section is a child
// route (/tenants/:id/general|groups|members|danger), so deep links work and
// the active entry is plain routerLinkActive. Left: the tenant's name over
// the section nav. Right: a header owned by the layout (the active section's
// search, the enabled toggle — persisted immediately) above the section's
// router outlet. The same screen serves root and the tenant's OWNER/ADMIN
// (the API scopes every call).
@Component({
  selector: 'app-tenant-page',
  providers: [TenantScope],
  imports: [
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatSelectModule,
    RouterLink,
    RouterLinkActive,
    RouterOutlet,
    LoadingIndicatorComponent,
    FormFieldComponent,
  ],
  templateUrl: './tenant-page.component.html',
  styleUrl: './tenant-page.component.scss',
})
export class TenantPageComponent {
  readonly id = input.required<string>();

  private readonly api = inject(ApiService);
  private readonly snack = inject(MatSnackBar);
  private readonly router = inject(Router);
  protected readonly scope = inject(TenantScope);

  protected readonly loading = signal(true);

  // The active child segment drives the header (which search to show).
  private readonly url = toSignal(
    this.router.events.pipe(
      filter((e) => e instanceof NavigationEnd),
      map(() => this.router.url),
    ),
    { initialValue: this.router.url },
  );
  protected readonly section = computed(() => this.url().split('/').pop() ?? '');

  constructor() {
    // The id input is router-bound: it changes when navigating from one tenant
    // to another — reload, and drop the previous tenant's search.
    effect(() => this.load(this.id()));
    effect(() => {
      this.section();
      this.scope.filter.set('');
      this.scope.tagFilter.set('');
    });
  }

  private load(id: string): void {
    this.loading.set(true);
    this.api.getTenant(id).subscribe({
      next: (tenant) => {
        this.scope.tenant.set(tenant);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

}
