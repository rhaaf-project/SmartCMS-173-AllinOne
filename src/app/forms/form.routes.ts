import { Routes } from '@angular/router';

export const FORMS_ROUTES: Routes = [
    { path: 'basic', loadComponent: () => import('./basic').then((d) => d.BasicComponent), data: { title: 'Forms' } },
    { path: 'input-group', loadComponent: () => import('./input-group').then((d) => d.InputGroupComponent), data: { title: 'Input Group' } },
    { path: 'layouts', loadComponent: () => import('./layouts').then((d) => d.LayoutsComponent), data: { title: 'Form Layouts' } },
    { path: 'validation', loadComponent: () => import('./validation').then((d) => d.ValidationComponent), data: { title: 'Form Validation' } },
    { path: 'input-mask', loadComponent: () => import('./input-mask').then((d) => d.InputMaskComponent), data: { title: 'Input Mask' } },
    { path: 'select2', loadComponent: () => import('./select2').then((d) => d.Select2Component), data: { title: 'Select2' } },
    { path: 'checkbox-radio', loadComponent: () => import('./checkbox-radio').then((d) => d.CheckboxRadioComponent), data: { title: 'Checkbox & Radio' } },
    { path: 'switches', loadComponent: () => import('./switches').then((d) => d.SwitchesComponent), data: { title: 'Switches' } },
    { path: 'wizards', loadComponent: () => import('./wizards').then((d) => d.WizardsComponent), data: { title: 'Wizards' } },
    { path: 'file-upload', loadComponent: () => import('./file-upload').then((d) => d.FileUploadComponent), data: { title: 'File Upload' } },
    { path: 'quill-editor', loadComponent: () => import('./quill-editor').then((d) => d.QuillEditorComponent), data: { title: 'Quill Editor' } },
    { path: 'date-picker', loadComponent: () => import('./date-picker').then((d) => d.DatePickerComponent), data: { title: 'Date & Range Picker' } },
    { path: 'clipboard', loadComponent: () => import('./clipboard').then((d) => d.ClipboardComponent), data: { title: 'Clipboard' } },
];
