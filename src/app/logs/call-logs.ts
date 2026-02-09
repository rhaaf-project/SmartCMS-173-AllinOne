import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../environments/environment';
import { IconEyeComponent } from '../shared/icon/icon-eye';
import { IconTrashLinesComponent } from '../shared/icon/icon-trash-lines';
import { IconXComponent } from '../shared/icon/icon-x';
import Swal from 'sweetalert2';

interface CallLog {
    id?: number;
    caller: string;
    callee: string;
    duration: number;
    status: 'answered' | 'missed' | 'busy' | 'failed';
    started_at?: string;
    ended_at?: string;
    channel_id?: number;
    created_at?: string;
}

@Component({
    selector: 'app-call-logs',
    standalone: true,
    imports: [CommonModule, IconEyeComponent, IconTrashLinesComponent, IconXComponent],
    templateUrl: './call-logs.html',
})
export class CallLogsComponent implements OnInit {
    logs: CallLog[] = [];
    selectedLog: CallLog | null = null;
    isLoading = false;
    showModal = false;

    constructor(private http: HttpClient) { }

    ngOnInit() {
        this.loadLogs();
    }

    loadLogs() {
        this.isLoading = true;
        this.http.get<{ success: boolean; data: CallLog[] }>(
            `${environment.apiUrl}/v1/call-logs`
        ).subscribe({
            next: (response) => {
                this.logs = response.data;
                this.isLoading = false;
            },
            error: (error) => {
                console.error('Error loading call logs:', error);
                Swal.fire('Error', 'Failed to load call logs', 'error');
                this.isLoading = false;
            }
        });
    }

    viewLog(log: CallLog) {
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
                this.http.delete(`${environment.apiUrl}/v1/call-logs/${id}`).subscribe({
                    next: () => {
                        Swal.fire('Deleted!', 'Call log has been deleted.', 'success');
                        this.loadLogs();
                    },
                    error: (error) => {
                        console.error('Error deleting call log:', error);
                        Swal.fire('Error', 'Failed to delete call log', 'error');
                    }
                });
            }
        });
    }

    closeModal() {
        this.showModal = false;
        this.selectedLog = null;
    }

    getStatusBadgeClass(status: string): string {
        const classes: Record<string, string> = {
            answered: 'badge-outline-success',
            missed: 'badge-outline-warning',
            busy: 'badge-outline-danger',
            failed: 'badge-outline-danger'
        };
        return classes[status] || 'badge-outline-secondary';
    }

    formatDuration(seconds: number): string {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;

        if (hours > 0) {
            return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
        }
        return `${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    }
}
