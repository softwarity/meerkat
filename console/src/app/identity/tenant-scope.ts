import { Injectable, signal } from '@angular/core';
import { Tenant } from '../api.service';

// Shared state between the tenant layout (left nav + right header) and its
// ROUTED sections: the loaded tenant (the layout owns loading, General updates
// it after a save) and the header search the matrices filter on. Provided by
// TenantPageComponent — one instance per visited tenant layout.
@Injectable()
export class TenantScope {
  readonly tenant = signal<Tenant | null>(null);
  readonly filter = signal('');
  // Groups section: the role tags available (published by the matrix) and the
  // single tag picked in the header ('' = all).
  readonly tags = signal<string[]>([]);
  readonly tagFilter = signal('');
}
