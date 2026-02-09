import { Routes } from '@angular/router';

export const ELEMENTS_ROUTES: Routes = [
    { path: 'alerts', loadComponent: () => import('./alerts').then((d) => d.AlertsComponent), data: { title: 'Alerts' } },
    { path: 'avatar', loadComponent: () => import('./avatar').then((d) => d.AvatarComponent), data: { title: 'Avatar' } },
    { path: 'badges', loadComponent: () => import('./badges').then((d) => d.BadgesComponent), data: { title: 'Badges' } },
    { path: 'breadcrumbs', loadComponent: () => import('./breadcrumbs').then((d) => d.BreadcrumbsComponent), data: { title: 'Breadcrumbs' } },
    { path: 'buttons', loadComponent: () => import('./buttons').then((d) => d.ButtonsComponent), data: { title: 'Buttons' } },
    { path: 'buttons-group', loadComponent: () => import('./buttons-group').then((d) => d.ButtonsGroupComponent), data: { title: 'Buttons Group' } },
    { path: 'color-library', loadComponent: () => import('./color-library').then((d) => d.ColorLibraryComponent), data: { title: 'Color Library' } },
    { path: 'dropdown', loadComponent: () => import('./dropdown').then((d) => d.DropdownComponent), data: { title: 'Dropdown' } },
    { path: 'infobox', loadComponent: () => import('./infobox').then((d) => d.InfoboxComponent), data: { title: 'Infobox' } },
    { path: 'jumbotron', loadComponent: () => import('./jumbotron').then((d) => d.JumbotronComponent), data: { title: 'Jumbotron' } },
    { path: 'loader', loadComponent: () => import('./loader').then((d) => d.LoaderComponent), data: { title: 'Loader' } },
    { path: 'pagination', loadComponent: () => import('./pagination').then((d) => d.PaginationComponent), data: { title: 'Pagination' } },
    { path: 'popovers', loadComponent: () => import('./popovers').then((d) => d.PopoversComponent), data: { title: 'Popovers' } },
    { path: 'progress-bar', loadComponent: () => import('./progress-bar').then((d) => d.ProgressBarComponent), data: { title: 'Progress Bar' } },
    { path: 'search', loadComponent: () => import('./search').then((d) => d.SearchComponent), data: { title: 'Search' } },
    { path: 'tooltips', loadComponent: () => import('./tooltips').then((d) => d.TooltipsComponent), data: { title: 'Tooltips' } },
    { path: 'treeview', loadComponent: () => import('./treeview').then((d) => d.TreeviewComponent), data: { title: 'Treeview' } },
    { path: 'typography', loadComponent: () => import('./typography').then((d) => d.TypographyComponent), data: { title: 'Typography' } },
];
