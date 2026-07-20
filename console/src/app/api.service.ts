import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

// One shape everywhere: these mirror the Go types (routing.Spec, store.Route,
// routing.CatalogEntry) — the console never invents its own model.
export interface Spec {
  type: string;
  args?: Record<string, unknown>;
}

export interface Route {
  id: string;
  name: string;
  order: number;
  enabled: boolean;
  authenticated: boolean;
  upstream: string;
  predicates: Spec[];
  filters: Spec[];
}

export interface Param {
  name: string;
  kind: 'string' | 'stringList' | 'int' | 'bool';
  required?: boolean;
  default?: unknown;
  doc?: string;
}

export interface CatalogEntry {
  kind: 'predicate' | 'filter';
  type: string;
  phase?: 'request' | 'response' | 'terminal';
  doc: string;
  params: Param[];
}

@Injectable({ providedIn: 'root' })
export class ApiService {
  private http = inject(HttpClient);

  catalog(): Observable<CatalogEntry[]> {
    return this.http.get<CatalogEntry[]>('/api/catalog');
  }

  listRoutes(): Observable<Route[]> {
    return this.http.get<Route[]>('/api/routes');
  }

  putRoute(route: Route): Observable<Route> {
    return this.http.put<Route>(`/api/routes/${encodeURIComponent(route.id)}`, route);
  }

  deleteRoute(id: string): Observable<void> {
    return this.http.delete<void>(`/api/routes/${encodeURIComponent(id)}`);
  }

  logout(): Observable<unknown> {
    return this.http.post('/logout', null, { responseType: 'text' });
  }
}
