import { Routes } from '@angular/router';

export const APPS_ROUTES: Routes = [
    { path: 'chat', loadComponent: () => import('./chat').then((d) => d.ChatComponent), data: { title: 'Chat' } },
    { path: 'mailbox', loadComponent: () => import('./mailbox').then((d) => d.MailboxComponent), data: { title: 'Mailbox' } },
    { path: 'scrumboard', loadComponent: () => import('./scrumboard').then((d) => d.ScrumboardComponent), data: { title: 'Scrumboard' } },
    { path: 'contacts', loadComponent: () => import('./contacts').then((d) => d.ContactsComponent), data: { title: 'Contacts' } },
    { path: 'notes', loadComponent: () => import('./notes').then((d) => d.NotesComponent), data: { title: 'Notes' } },
    { path: 'todolist', loadComponent: () => import('./todolist').then((d) => d.TodolistComponent), data: { title: 'Todolist' } },
    { path: 'invoice/list', loadComponent: () => import('./invoice/list').then((d) => d.InvoiceListComponent), data: { title: 'Invoice List' } },
    { path: 'invoice/preview', loadComponent: () => import('./invoice/preview').then((d) => d.InvoicePreviewComponent), data: { title: 'Invoice Preview' } },
    { path: 'invoice/add', loadComponent: () => import('./invoice/add').then((d) => d.InvoiceAddComponent), data: { title: 'Invoice Add' } },
    { path: 'invoice/edit', loadComponent: () => import('./invoice/edit').then((d) => d.InvoiceEditComponent), data: { title: 'Invoice Edit' } },
    { path: 'calendar', loadComponent: () => import('./calendar').then((d) => d.CalendarComponent), data: { title: 'Calendar' } },
];
