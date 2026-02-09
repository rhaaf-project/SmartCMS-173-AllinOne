import { Routes } from '@angular/router';

export const COMPONENTS_ROUTES: Routes = [
    { path: 'tabs', loadComponent: () => import('./tabs').then((d) => d.TabsComponent), data: { title: 'Tabs' } },
    { path: 'accordions', loadComponent: () => import('./accordions').then((d) => d.AccordionsComponent), data: { title: 'Accordions' } },
    { path: 'modals', loadComponent: () => import('./modals').then((d) => d.ModalsComponent), data: { title: 'Modals' } },
    { path: 'cards', loadComponent: () => import('./cards').then((d) => d.CardsComponent), data: { title: 'Cards' } },
    { path: 'carousel', loadComponent: () => import('./carousel').then((d) => d.CarouselComponent), data: { title: 'Carousel' } },
    { path: 'countdown', loadComponent: () => import('./countdown').then((d) => d.CountdownComponent), data: { title: 'Countdown' } },
    { path: 'counter', loadComponent: () => import('./counter').then((d) => d.CounterComponent), data: { title: 'Counter' } },
    { path: 'sweetalert', loadComponent: () => import('./sweetalert').then((d) => d.SweetalertComponent), data: { title: 'Sweetalert' } },
    { path: 'timeline', loadComponent: () => import('./timeline').then((d) => d.TimelineComponent), data: { title: 'Timeline' } },
    { path: 'notifications', loadComponent: () => import('./notifications').then((d) => d.NotificationsComponent), data: { title: 'Notifications' } },
    { path: 'media-object', loadComponent: () => import('./media-object').then((d) => d.MediaObjectComponent), data: { title: 'Media Object' } },
    { path: 'list-group', loadComponent: () => import('./list-group').then((d) => d.ListGroupComponent), data: { title: 'List Group' } },
    { path: 'pricing-table', loadComponent: () => import('./pricing-table').then((d) => d.PricingTableComponent), data: { title: 'Pricing Table' } },
    { path: 'lightbox', loadComponent: () => import('./lightbox').then((d) => d.LightboxComponent), data: { title: 'Lightbox' } },
];
