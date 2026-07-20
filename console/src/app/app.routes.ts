import { Routes } from '@angular/router';

export const routes: Routes = [
  { path: '', pathMatch: 'full', redirectTo: 'routes' },
  {
    path: 'routes',
    loadComponent: () => import('./routes/routes-page.component').then((m) => m.RoutesPageComponent),
  },
  { path: '**', redirectTo: 'routes' },
];
