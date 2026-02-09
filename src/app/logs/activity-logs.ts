import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../environments/environment';
import { IconEyeComponent } from '../shared/icon/icon-eye';
import { IconTrashLinesComponent } from '../shared/icon/icon-trash-lines';
import { IconXComponent } from '../shared/icon/icon-x';
import Swal from 'sweetalert2';

interface ActivityLog {
    id?: number;
    user_id?: number;
    user?: { id: number; name: string; email: string };
    action: string;
    entity_type?: string;
    entity_id?: number;
    old_values?: string;
    new_values?: string;
    ip_address?: string;
    user_agent?: string;
    created_at?: string;
}

@Component({
    selector: 'app-activity-logs',
    standalone: true,
    imports: [CommonModule, IconEyeComponent, IconTrashLinesComponent, IconXComponent],
    templateUrl: './activity-logs.html',
})
export class ActivityLogsComponent implements OnInit {
    logs: ActivityLog[] = [];
    selectedLog: ActivityLog | null = null;
    isLoading = false;
    showModal = false;

    constructor(private http: HttpClient) { }

    ngOnInit() {
        this.loadLogs();
    }

    loadLogs() {
        this.isLoading = true;
        this.http.get<{ success: boolean; data: ActivityLog[] }>(
            `${environment.apiUrl}/v1/activity-logs`
        ).subscribe({
            next: (response) => {
                this.logs = response.data;
                this.isLoading = false;
            },
            error: (error) => {
                console.error('Error loading activity logs:', error);
                Swal.fire('Error', 'Failed to load activity logs', 'error');
                this.isLoading = false;
            }
        });
    }

    viewLog(log: ActivityLog) {
        this.selectedLog = { ...log };
        this.showModal = true;
    }

    deleteLog(id: number) {
        Swal.fire({
            title: 'Are you sure?',
            text: "You won't be able to revert this!",
            icon: 'warning',
            showCancelButton: true,
            confirmButtonText: 'Yes, delete it!',
            cancelButtonText: 'Cancel'
        }).then((result) => {
            if (result.isConfirmed) {
                this.http.delete(`${environment.apiUrl}/v1/activity-logs/${id}`).subscribe({
                    next: () => {
                        Swal.fire('Deleted!', 'Activity log has been deleted.', 'success');
                        this.loadLogs();
                    },
                    error: (error) => {
                        console.error('Error deleting activity log:', error);
                        Swal.fire('Error', 'Failed to delete activity log', 'error');
                    }
                });
            }
        });
    }

    closeModal() {
        this.showModal = false;
        this.selectedLog = null;
    }

    getActionBadgeClass(action: string): string {
        const classes: Record<string, string> = {
            created: 'badge-outline-success',
            updated: 'badge-outline-info',
            deleted: 'badge-outline-danger',
            viewed: 'badge-outline-secondary',
            login: 'badge-outline-success',
            logout: 'badge-outline-warning',
            login_failed: 'badge-outline-danger',
        };
        return classes[action.toLowerCase()] || 'badge-outline-primary';
    }

    getDisplayName(log: ActivityLog): string {
        // First check if user relation exists
        if (log.user?.name) {
            return log.user.name;
        }

        // Try to parse from new_values JSON - prioritize email for full identification
        if (log.new_values) {
            try {
                const data = JSON.parse(log.new_values);
                if (data.email) return data.email;
                if (data.name) return data.name;
            } catch (e) {
                // Not valid JSON
            }
        }

        return 'System';
    }

    getLogoutTime(log: ActivityLog): string | null {
        // For login records, find matching logout
        if (log.action === 'login' && log.new_values) {
            try {
                const data = JSON.parse(log.new_values);
                const email = data.email;

                // Find next logout for this email after this login
                const loginTime = new Date(log.created_at || '');
                const matchingLogout = this.logs.find(l => {
                    if (l.action !== 'logout' || !l.new_values) return false;
                    try {
                        const logoutData = JSON.parse(l.new_values);
                        const logoutTime = new Date(l.created_at || '');
                        return logoutData.email === email && logoutTime > loginTime;
                    } catch { return false; }
                });

                if (matchingLogout) {
                    return matchingLogout.created_at || null;
                }
            } catch (e) { }
        }
        return null;
    }
}
