import { Routes } from '@angular/router';

export const routes: Routes = [
    {
        path: 'static-route',
        loadComponent: () => import('./static-route').then((c) => c.StaticRouteComponent),
    },
    {
        path: 'firewall',
        loadComponent: () => import('./firewall').then((c) => c.FirewallComponent),
    },
];
