import { Service, inject, signal } from '@angular/core';
import { catchError, of } from 'rxjs';
import { ApiService, Tenant } from '../api.service';

// The organisations the caller may see, loaded once and shared (the API scopes
// the list itself: root sees all, an admin sees theirs).
//
// It exists because the rail's drawer is not where organisations are created,
// renamed or deleted: those happen on screens the drawer knows nothing about.
// Without a shared signal a deleted organisation stayed in the drawer until a
// reload, offering a link to something that no longer existed - and a rename
// left the old name there, which is worse: nothing looks broken.
@Service()
export class TenantsService {
  private readonly api = inject(ApiService);

  readonly tenants = signal<Tenant[]>([]);

  // A failure resolves to an empty list rather than an error: the drawer is
  // navigation, and a caller with no organisation is a normal state, not an
  // incident.
  reload(): void {
    this.api
      .listTenants()
      .pipe(catchError(() => of<Tenant[]>([])))
      .subscribe((list) => this.tenants.set(list));
  }

  // Applies a change locally AND asks the server again. The local touch is
  // what makes the drawer follow the click without a round-trip; the reload is
  // what keeps it honest when the server saw things differently.
  remove(id: string): void {
    this.tenants.update((list) => list.filter((t) => t.id !== id));
    this.reload();
  }

  replace(tenant: Tenant): void {
    this.tenants.update((list) => list.map((t) => (t.id === tenant.id ? tenant : t)));
    this.reload();
  }
}
