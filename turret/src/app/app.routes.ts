import { Routes } from '@angular/router';

export const routes: Routes = [
  {
    path: 'turret',
    loadComponent: () => import('./pages/turret/turret.page').then((m) => m.TurretPage),
  },
  {
    path: 'home',
    loadComponent: () => import('./home/home.page').then((m) => m.HomePage),
  },
  {
    path: '',
    redirectTo: 'turret',
    pathMatch: 'full',
  },
];
