import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../environments/environment';
import { IconEyeComponent } from '../shared/icon/icon-eye';
import { IconTrashLinesComponent } from '../shared/icon/icon-trash-lines';
import { IconXComponent } from '../shared/icon/icon-x';
import Swal from 'sweetalert2';

interface SystemLog {
    id?: number;
    level: 'debug' | 'info' | 'warning' | 'error' | 'critical';
    message: string;
    context: string | null;
    created_at?: string;
}

@Component({
    selector: 'app-system-logs',
    standalone: true,
    imports: [CommonModule, IconEyeComponent, IconTrashLinesComponent, IconXComponent],
    templateUrl: './system-logs.html',
})
export class SystemLogsComponent implements OnInit {
    logs: SystemLog[] = [];
    selectedLog: SystemLog | null = null;
    isLoading = false;
    showModal = false;

    constructor(private http: HttpClient) { }

    ngOnInit() {
        this.loadLogs();
    }

    loadLogs() {
        this.isLoading = true;
        this.http.get<{ success: boolean; data: SystemLog[] }>(
            `${environment.apiUrl}/v1/system-logs`
        ).subscribe({
            next: (response) => {
                this.logs = response.data;
                this.isLoading = false;
            },
            error: (error) => {
                console.error('Error loading system logs:', error);
                Swal.fire('Error', 'Failed to load system logs', 'error');
                this.isLoading = false;
            }
        });
    }

    viewLog(log: SystemLog) {
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
                this.http.delete(`${environment.apiUrl}/v1/system-logs/${id}`).subscribe({
                    next: () => {
                        Swal.fire('Deleted!', 'System log has been deleted.', 'success');
                        this.loadLogs();
                    },
                    error: (error) => {
                        console.error('Error deleting system log:', error);
                        Swal.fire('Error', 'Failed to delete system log', 'error');
                    }
                });
            }
        });
    }

    closeModal() {
        this.showModal = false;
        this.selectedLog = null;
    }

    getLevelBadgeClass(level: string): string {
        const classes: Record<string, string> = {
            debug: 'badge-outline-secondary',
            info: 'badge-outline-info',
            warning: 'badge-outline-warning',
            error: 'badge-outline-danger',
            critical: 'badge-outline-danger'
        };
        return classes[level] || 'badge-outline-secondary';
    }
}
