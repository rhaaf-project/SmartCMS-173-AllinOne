import { Routes } from '@angular/router';

export const USERS_ROUTES: Routes = [
    {
        path: 'user-account-settings',
        loadComponent: () => import('./user-account-settings').then((d) => d.UserAccountSettingsComponent),
        data: { title: 'Account Setting' },
    },
    { path: 'profile', loadComponent: () => import('./profile').then((d) => d.ProfileComponent), data: { title: 'User Profile' } },
];
