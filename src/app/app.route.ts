import { Routes } from '@angular/router';

// layouts
import { AppLayout } from './layouts/app-layout';
import { AuthLayout } from './layouts/auth-layout';

import { NotFoundComponent } from './not-found';
import { NAComponent } from './shared/na/na';
import { AuthGuard } from '../auth.guard';

export const routes: Routes = [
    // Default route - redirect to admin
    {
        path: '',
        redirectTo: '/admin',
        pathMatch: 'full',
    },
    { path: 'ping-na', component: NAComponent },

    // Admin protected route
    {
        path: 'admin',
        component: AppLayout,
        canActivate: [AuthGuard],
        children: [
            // dashboard
            { path: '', loadComponent: () => import('./index').then((d) => d.IndexComponent), data: { title: 'Dashboard | SmartUCX' } },
            { path: 'analytics', loadComponent: () => import('./analytics').then((d) => d.AnalyticsComponent), data: { title: 'Analytics | SmartUCX' } },
            { path: 'finance', loadComponent: () => import('./finance').then((d) => d.FinanceComponent), data: { title: 'Finance | SmartUCX' } },
            { path: 'crypto', loadComponent: () => import('./crypto').then((d) => d.CryptoComponent), data: { title: 'Crypto | SmartUCX' } },

            // widgets
            { path: 'widgets', loadComponent: () => import('./widgets').then((d) => d.WidgetsComponent), data: { title: 'Widgets | SmartUCX' } },

            // font-icons
            { path: 'font-icons', loadComponent: () => import('./font-icons').then((d) => d.FontIconsComponent), data: { title: 'Font Icons | SmartUCX' } },

            // charts
            { path: 'charts', loadComponent: () => import('./charts').then((d) => d.ChartsComponent), data: { title: 'Charts | SmartUCX' } },

            // dragndrop
            { path: 'dragndrop', loadComponent: () => import('./dragndrop').then((d) => d.DragndropComponent), data: { title: 'Drag & Drop | SmartUCX' } },

            // pages
            {
                path: 'pages/knowledge-base',
                loadComponent: () => import('./pages/knowledge-base').then((d) => d.KnowledgeBaseComponent),
                data: { title: 'Knowledge Base | SmartUCX' },
            },
            { path: 'pages/faq', loadComponent: () => import('./pages/faq').then((d) => d.FaqComponent), data: { title: 'FAQ | SmartUCX' } },

            //apps
            { path: 'apps', loadChildren: () => import('./apps/apps.routes').then((d) => d.APPS_ROUTES) },

            // components
            { path: 'components', loadChildren: () => import('./components/components.routes').then((d) => d.COMPONENTS_ROUTES) },

            // elements
            { path: 'elements', loadChildren: () => import('./elements/elements.routes').then((d) => d.ELEMENTS_ROUTES) },

            // forms
            { path: 'forms', loadChildren: () => import('./forms/form.routes').then((d) => d.FORMS_ROUTES) },

            // users
            { path: 'users', loadChildren: () => import('./users/user.routes').then((d) => d.USERS_ROUTES) },

            // tables
            { path: 'tables', loadComponent: () => import('./tables').then((d) => d.TablesComponent), data: { title: 'Tables | SmartUCX' } },
            { path: 'datatables', loadChildren: () => import('./datatables/datatables.routes').then((d) => d.DATATABLES_ROUTES) },

            // organization
            { path: 'organization', loadChildren: () => import('./organization/organization.routes').then((d) => d.ORGANIZATION_ROUTES) },

            // connectivity
            { path: 'connectivity', loadChildren: () => import('./connectivity/connectivity.routes').then((d) => d.CONNECTIVITY_ROUTES) },
            // logs
            { path: 'logs', loadChildren: () => import('./logs/logs.routes').then((d) => d.logsRoutes) },

            // CMS Administration
            {
                path: 'cms-admin/layout-customizer',
                loadComponent: () => import('./cms-admin/layout-customizer').then((d) => d.LayoutCustomizerComponent),
                data: { title: 'Layout Customizer | SmartUCX' }
            },
            {
                path: 'cms-admin/user-management',
                loadComponent: () => import('./cms-admin/cms-users').then((d) => d.CmsUsersComponent),
                data: { title: 'CMS User Management | SmartUCX' }
            },

            // Unimplemented Modules (NA)
            { path: 'voice-gateway', component: NAComponent },
            { path: 'voice-gateway/:any', component: NAComponent },
            { path: 'voice-gateway/:any/:any2', component: NAComponent },
            { path: 'recording', component: NAComponent },
            { path: 'recording/:any', component: NAComponent },
            { path: 'recording/:any/:any2', component: NAComponent },
            { path: 'device', component: NAComponent },
            {
                path: 'device/3rd-party-device',
                loadComponent: () => import('./device/third-party-device/third-party-device').then((d) => d.ThirdPartyDeviceComponent),
                data: { title: '3rd Party Device | SmartUCX', pageKey: 'device.third_party_device' },
                canActivate: [AuthGuard],
            },
            { path: 'device/:any', component: NAComponent },
            { path: 'device/:any/:any2', component: NAComponent },
            // Turret Management
            {
                path: 'turret-management/users',
                loadComponent: () => import('./turret-management/turret-users').then((d) => d.TurretUsersComponent),
                data: { title: 'Turret Users | SmartUCX' }
            },
            // NA for other turret-management submenus not yet implemented
            {
                path: 'turret-management/template',
                loadComponent: () => import('./turret-management/turret-template').then((d) => d.TurretTemplateComponent),
                data: { title: 'Turret Templates | SmartUCX' }
            },
            {
                path: 'turret-management/group',
                loadComponent: () => import('./turret-management/turret-group').then((d) => d.TurretGroupComponent),
                data: { title: 'Turret Groups | SmartUCX' }
            },
            {
                path: 'turret-management/policy',
                loadComponent: () => import('./turret-management/turret-policy').then((d) => d.TurretPolicyComponent),
                data: { title: 'Turret Policies | SmartUCX' }
            },
            {
                path: 'turret-management/phone-directory',
                loadComponent: () => import('./turret-management/phone-directory').then((d) => d.PhoneDirectoryComponent),
                data: { title: 'Phone Directory | SmartUCX' }
            },
            // network
            { path: 'network', loadChildren: () => import('./network/network.routes').then((d) => d.routes) },
            { path: 'backup', component: NAComponent },
            { path: 'backup/:any', component: NAComponent },
            { path: 'backup/:any/:any2', component: NAComponent },
            {
                path: 'cms-admin/group',
                loadComponent: () => import('./cms-admin/cms-na/cms-na').then((d) => d.CMSNAComponent),
                data: { title: 'CMS Group | SmartUCX' }
            },
            {
                path: 'cms-admin/policy',
                loadComponent: () => import('./cms-admin/cms-na/cms-na').then((d) => d.CMSNAComponent),
                data: { title: 'CMS Policy | SmartUCX' }
            },
        ],
    },

    // Root-level NA redirects (if /admin is missed) using AppLayout
    {
        path: '',
        component: AppLayout,
        // canActivate: [AuthGuard],
        children: [
            { path: 'voice-gateway', component: NAComponent },
            { path: 'voice-gateway/:any', component: NAComponent },
            { path: 'recording', component: NAComponent },
            { path: 'recording/:any', component: NAComponent },
            { path: 'device', component: NAComponent },
            { path: 'device/:any', component: NAComponent },
            { path: 'turret-management', component: NAComponent },
            { path: 'turret-management/:any', component: NAComponent },
            { path: 'backup', component: NAComponent },
            { path: 'backup/:any', component: NAComponent },
        ]
    },

    {
        path: '',
        component: AuthLayout,
        children: [
            // direct login page
            { path: 'login', loadComponent: () => import('./auth/boxed-signin').then((d) => d.BoxedSigninComponent), data: { title: 'Login | SmartUCX' } },

            // pages
            { path: 'pages', loadChildren: () => import('./pages/pages.routes').then((d) => d.PAGES_ROUTES) },

            // auth
            { path: 'auth', loadChildren: () => import('./auth/auth.routes').then((d) => d.AUTH_ROUTES) },
        ],
    },

    // Catch-all - 404
    { path: '**', loadComponent: () => import('./not-found').then((d) => d.NotFoundComponent) },
];

