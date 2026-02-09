import { Routes } from '@angular/router';

export const AUTH_ROUTES: Routes = [
    {
        path: 'boxed-lockscreen',
        loadComponent: () => import('./boxed-lockscreen').then((d) => d.BoxedLockscreenComponent),
        data: { title: 'Boxed Lockscreen' },
    },
    {
        path: 'boxed-password-reset',
        loadComponent: () => import('./boxed-password-reset').then((d) => d.BoxedPasswordResetComponent),
        data: { title: 'Boxed Password Reset' },
    },
    {
        path: 'boxed-signin',
        loadComponent: () => import('./boxed-signin').then((d) => d.BoxedSigninComponent),
        data: { title: 'Boxed Signin' },
    },
    {
        path: 'boxed-signup',
        loadComponent: () => import('./boxed-signup').then((d) => d.BoxedSignupComponent),
        data: { title: 'Boxed Signup' },
    },
    {
        path: 'cover-lockscreen',
        loadComponent: () => import('./cover-lockscreen').then((d) => d.CoverLockscreenComponent),
        data: { title: 'Cover Lockscreen' },
    },
    {
        path: 'cover-login',
        loadComponent: () => import('./cover-login').then((d) => d.CoverLoginComponent),
        data: { title: 'Cover Login' },
    },
    {
        path: 'cover-password-reset',
        loadComponent: () => import('./cover-password-reset').then((d) => d.CoverPasswordResetComponent),
        data: { title: 'Cover Password Reset' },
    },
    {
        path: 'cover-register',
        loadComponent: () => import('./cover-register').then((d) => d.CoverRegisterComponent),
        data: { title: 'Cover Register' },
    },
];
