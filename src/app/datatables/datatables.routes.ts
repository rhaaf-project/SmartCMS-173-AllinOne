import { Routes } from '@angular/router';

export const DATATABLES_ROUTES: Routes = [
    { path: 'basic', loadComponent: () => import('./basic').then((d) => d.BasicDatatableComponent), data: { title: 'Basic Table' } },
    { path: 'advanced', loadComponent: () => import('./advanced').then((d) => d.AdvancedDatatableComponent), data: { title: 'Advanced Table' } },
    { path: 'skin', loadComponent: () => import('./skin').then((d) => d.SkinDatatableComponent), data: { title: 'Skin Table' } },
    {
        path: 'order-sorting',
        loadComponent: () => import('./order-sorting').then((d) => d.OrderSortingDatatableComponent),
        data: { title: 'Order Sorting Table' },
    },
    {
        path: 'columns-filter',
        loadComponent: () => import('./columns-filter').then((d) => d.ColumnsFilterDatatableComponent),
        data: { title: 'Columns Filter Table' },
    },
    {
        path: 'multi-column',
        loadComponent: () => import('./multi-column').then((d) => d.MultiColumnDatatableComponent),
        data: { title: 'Multi Column Table' },
    },
    {
        path: 'multiple-tables',
        loadComponent: () => import('./multiple-tables').then((d) => d.MultiTablesComponent),
        data: { title: 'Multiple Tables' },
    },
    {
        path: 'alt-pagination',
        loadComponent: () => import('./alt-pagination').then((d) => d.AltPaginationDatatableComponent),
        data: { title: 'Alternative Pagination' },
    },
    {
        path: 'checkbox',
        loadComponent: () => import('./checkbox').then((d) => d.CheckboxDatatableComponent),
        data: { title: 'Checkbox Table' },
    },
    {
        path: 'range-search',
        loadComponent: () => import('./range-search').then((d) => d.RangeSearchDatatableComponent),
        data: { title: 'Range Search Table' },
    },
    {
        path: 'export',
        loadComponent: () => import('./export').then((d) => d.ExportDatatableComponent),
        data: { title: 'Export Table' },
    },
    {
        path: 'sticky-header',
        loadComponent: () => import('./sticky-header').then((d) => d.StickyHeaderDatatableComponent),
        data: { title: 'Sticky Header' },
    },
    {
        path: 'clone-header',
        loadComponent: () => import('./clone-header').then((d) => d.CloneHeaderDatatableComponent),
        data: { title: 'Clone Header Table' },
    },
    {
        path: 'column-chooser',
        loadComponent: () => import('./column-chooser').then((d) => d.ColumnChooserDatatableComponent),
        data: { title: 'Column Chooser Table' },
    },
];
