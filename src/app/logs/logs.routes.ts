import { Routes } from '@angular/router';

export const logsRoutes: Routes = [
    {
        path: 'system-logs',
        loadComponent: () => import('./system-logs').then((d) => d.SystemLogsComponent),
        title: 'System Logs | SmartUCX',
    },
    {
        path: 'activity-logs',
        loadComponent: () => import('./activity-logs').then((d) => d.ActivityLogsComponent),
        title: 'Activity Logs | SmartUCX',
    },
    {
        path: 'call-logs',
        loadComponent: () => import('./call-logs').then((d) => d.CallLogsComponent),
        title: 'Call Logs | SmartUCX',
    },
    {
        path: 'alarm-notification',
        loadComponent: () => import('./alarm-notification').then((d) => d.AlarmNotificationComponent),
        title: 'Alarm & Notification | SmartUCX',
    },
    {
        path: 'usage-report',
        loadComponent: () => import('./usage-report').then((d) => d.UsageReportComponent),
        title: 'Usage Report | SmartUCX',
    },
];
