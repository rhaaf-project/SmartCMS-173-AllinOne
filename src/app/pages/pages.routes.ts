import { Routes } from '@angular/router';

export const PAGES_ROUTES: Routes = [
    {
        path: 'contact-us-boxed',
        loadComponent: () => import('./contact-us-boxed').then((d) => d.ContactUsBoxedComponent),
        data: { title: 'Contact Us Boxed' },
    },
    {
        path: 'contact-us-cover',
        loadComponent: () => import('./contact-us-cover').then((d) => d.ContactUsCoverComponent),
        data: { title: 'Contact Us Cover' },
    },
    {
        path: 'coming-soon-boxed',
        loadComponent: () => import('./coming-soon-boxed').then((d) => d.ComingSoonBoxedComponent),
        data: { title: 'Coming Soon Boxed' },
    },
    {
        path: 'coming-soon-cover',
        loadComponent: () => import('./coming-soon-cover').then((d) => d.ComingSoonCoverComponent),
        data: { title: 'Coming Soon Cover' },
    },
    {
        path: 'error404',
        loadComponent: () => import('./error404').then((d) => d.Error404Component),
        data: { title: 'Error 404' },
    },
    {
        path: 'error500',
        loadComponent: () => import('./error500').then((d) => d.Error500Component),
        data: { title: 'Error 500' },
    },
    {
        path: 'error503',
        loadComponent: () => import('./error503').then((d) => d.Error503Component),
        data: { title: 'Error 503' },
    },
    {
        path: 'maintenence',
        loadComponent: () => import('./maintenence').then((d) => d.MaintenenceComponent),
        data: { title: 'Maintenence' },
    },
];
