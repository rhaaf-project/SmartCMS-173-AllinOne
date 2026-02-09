import { Routes } from '@angular/router';

export const ORGANIZATION_ROUTES: Routes = [
    // Connectivity Diagram
    {
        path: 'connectivity-diagram',
        loadComponent: () => import('./connectivity-diagram/connectivity-diagram').then((d) => d.ConnectivityDiagramComponent),
        data: { title: 'Connectivity Diagram | SmartUCX' },
    },
    // Company routes
    {
        path: 'company',
        loadComponent: () => import('./company/company-list').then((d) => d.CompanyListComponent),
        data: { title: 'Company | SmartUCX' },
    },
    // Head Office routes
    {
        path: 'head-office',
        loadComponent: () => import('./head-office/head-office-list').then((d) => d.HeadOfficeListComponent),
        data: { title: 'Head Office | SmartUCX' },
    },
    // Branch routes
    {
        path: 'branch',
        loadComponent: () => import('./branch/branch-list').then((d) => d.BranchListComponent),
        data: { title: 'Branch | SmartUCX' },
    },
    // Sub Branch routes
    {
        path: 'sub-branch',
        loadComponent: () => import('./sub-branch/sub-branch-list').then((d) => d.SubBranchListComponent),
        data: { title: 'Sub Branch | SmartUCX' },
    },
];

