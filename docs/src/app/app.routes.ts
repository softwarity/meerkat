import { Routes } from '@angular/router';

export const routes: Routes = [
  {
    path: '',
    pathMatch: 'full',
    loadComponent: () => import('./pages/about.component').then((m) => m.AboutComponent),
  },
  {
    path: 'requirements',
    loadComponent: () =>
      import('./pages/requirements.component').then((m) => m.RequirementsComponent),
  },
  {
    path: 'dev-mode',
    loadComponent: () => import('./pages/dev-mode.component').then((m) => m.DevModeComponent),
  },
  {
    path: 'roadmap',
    loadComponent: () => import('./pages/roadmap.component').then((m) => m.RoadmapComponent),
  },
  { path: '**', redirectTo: '' },
];
