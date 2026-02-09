import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../environments/environment';
import { IconEyeComponent } from '../shared/icon/icon-eye';
import { IconTrashLinesComponent } from '../shared/icon/icon-trash-lines';
import { IconXComponent } from '../shared/icon/icon-x';
import Swal from 'sweetalert2';

interface AlarmNotification {
    id?: number;
    type: 'alarm' | 'notification';
    severity: 'low' | 'medium' | 'high' | 'critical';
    title: string;
    message: string;
    is_read: boolean;
    created_at?: string;
}

@Component({
    selector: 'app-alarm-notification',
    standalone: true,
    imports: [CommonModule, IconEyeComponent, IconTrashLinesComponent, IconXComponent],
    templateUrl: './alarm-notification.html',
})
export class AlarmNotificationComponent implements OnInit {
    notifications: AlarmNotification[] = [];
    selectedNotification: AlarmNotification | null = null;
    isLoading = false;
    showModal = false;

    constructor(private http: HttpClient) { }

    ngOnInit() {
        this.loadNotifications();
    }

    loadNotifications() {
        this.isLoading = true;
        const apiUrl = `${environment.apiUrl}/v1/alarm-notifications`;

        this.http.get<any>(apiUrl).subscribe({
            next: (response) => {
                this.notifications = response.data || [];
                this.isLoading = false;
            },
            error: (error) => {
                console.error('Failed to load alarm notifications:', error);
                this.isLoading = false;
            },
        });
    }

    viewNotification(notification: AlarmNotification) {
        this.selectedNotification = notification;
        this.showModal = true;
    }

    closeModal() {
        this.showModal = false;
        this.selectedNotification = null;
    }

    deleteNotification(id: number) {
        Swal.fire({
            title: 'Are you sure?',
            text: 'This notification will be deleted permanently!',
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#3085d6',
            cancelButtonColor: '#d33',
            confirmButtonText: 'Yes, delete it!',
        }).then((result) => {
            if (result.isConfirmed) {
                const apiUrl = `${environment.apiUrl}/v1/alarm-notifications/${id}`;

                this.http.delete<any>(apiUrl).subscribe({
                    next: () => {
                        Swal.fire('Deleted!', 'Notification has been deleted.', 'success');
                        this.loadNotifications();
                    },
                    error: (error) => {
                        console.error('Failed to delete notification:', error);
                        Swal.fire('Error!', 'Failed to delete notification.', 'error');
                    },
                });
            }
        });
    }

    getSeverityClass(severity: string): string {
        switch (severity) {
            case 'critical': return 'badge-outline-danger';
            case 'high': return 'badge-outline-warning';
            case 'medium': return 'badge-outline-info';
            default: return 'badge-outline-success';
        }
    }
}
