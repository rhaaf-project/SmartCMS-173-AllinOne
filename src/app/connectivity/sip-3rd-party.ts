import { Component, inject, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { Router, RouterModule } from '@angular/router';
import { Store } from '@ngrx/store';
import { toggleAnimation } from '../shared/animations';
import { environment } from '../../environments/environment';
import { IconPlusComponent } from '../shared/icon/icon-plus';
import { IconPencilComponent } from '../shared/icon/icon-pencil';
import { IconTrashLinesComponent } from '../shared/icon/icon-trash-lines';
import { IconCircleCheckComponent } from '../shared/icon/icon-circle-check';
import { IconCopyComponent } from '../shared/icon/icon-copy';
import Swal from 'sweetalert2';

interface SipLine {
    id?: number;
    call_server_id: number | null;
    call_server?: {
        id: number;
        name: string;
    };
    name: string;
    line_number: string;
    type: string;
    channel_count: number;
    trunk_id: number | null;
    description: string | null;
    secret: string | null;
    is_active: boolean;
    created_at?: string;
    updated_at?: string;
}

interface CallServer {
    id: number;
    name: string;
}

@Component({
    templateUrl: './sip-3rd-party.html',
    animations: [toggleAnimation],
    imports: [
        CommonModule,
        FormsModule,
        RouterModule,
        IconPlusComponent,
        IconPencilComponent,
        IconTrashLinesComponent,
        IconCircleCheckComponent,
        IconCopyComponent,
    ],
})
export class Sip3rdPartyComponent implements OnInit {
    store: any;
    lines: SipLine[] = [];
    callServers: CallServer[] = [];
    isLoading = false;
    search = '';
    showModal = false;
    modalMode: 'create' | 'edit' | 'view' = 'create';

    formData: SipLine = {
        call_server_id: null,
        name: '',
        line_number: '',
        type: 'pjsip',
        channel_count: 1,
        trunk_id: null,
        description: null,
        secret: null,
        is_active: true,
    };

    private http = inject(HttpClient);

    constructor(
        public storeData: Store<any>,
        public router: Router
    ) {
        this.initStore();
    }

    async initStore() {
        this.storeData
            .select((d) => d.index)
            .subscribe((d) => {
                this.store = d;
            });
    }

    ngOnInit() {
        this.loadLines();
        this.loadCallServers();
    }

    loadLines() {
        this.isLoading = true;
        const apiUrl = `${environment.apiUrl}/v1/lines`;

        this.http.get<any>(apiUrl).subscribe({
            next: (response) => {
                // Filter for WS/PJSIP type lines only
                const allLines = response.data || [];
                this.lines = allLines.filter((l: SipLine) => l.type === 'pjsip' || l.type === 'ws');
                this.isLoading = false;
            },
            error: (error) => {
                console.error('Failed to load SIP/3rd Party lines:', error);
                this.isLoading = false;
                this.showErrorMessage('Failed to load lines');
            },
        });
    }

    loadCallServers() {
        const apiUrl = `${environment.apiUrl}/v1/call-servers`;

        this.http.get<any>(apiUrl).subscribe({
            next: (response) => {
                this.callServers = response.data || [];
            },
            error: (error) => {
                console.error('Failed to load call servers:', error);
            },
        });
    }

    openCreateModal() {
        this.modalMode = 'create';
        this.resetForm();
        this.showModal = true;
    }

    openEditModal(line: SipLine) {
        this.modalMode = 'edit';
        this.formData = { ...line };
        this.showModal = true;
    }

    openViewModal(line: SipLine) {
        this.modalMode = 'view';
        this.formData = { ...line };
        this.showModal = true;
    }

    copyRecord(line: SipLine) {
        this.modalMode = 'create';
        this.formData = { ...line, id: undefined, name: line.name + ' - Copy', line_number: line.line_number + '-copy' };
        this.showModal = true;
    }

    closeModal() {
        this.showModal = false;
        this.resetForm();
    }

    generateRandomSecret(length = 10): string {
        const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
        let retVal = '';
        for (let i = 0, n = charset.length; i < length; ++i) {
            retVal += charset.charAt(Math.floor(Math.random() * n));
        }
        return retVal;
    }

    resetForm() {
        this.formData = {
            call_server_id: null,
            name: '',
            line_number: '',
            type: 'pjsip',
            channel_count: 1,
            trunk_id: null,
            description: null,
            secret: this.generateRandomSecret(),
            is_active: true,
        };
    }

    handleSubmit() {
        if (this.modalMode === 'create') {
            this.createLine();
        } else if (this.modalMode === 'edit') {
            this.updateLine();
        }
    }

    createLine() {
        const apiUrl = `${environment.apiUrl}/v1/lines`;

        const createData = {
            call_server_id: this.formData.call_server_id,
            name: this.formData.name,
            line_number: this.formData.line_number,
            type: this.formData.type || 'pjsip',
            channel_count: this.formData.channel_count || 1,
            trunk_id: this.formData.trunk_id,
            description: this.formData.description,
            secret: this.formData.secret,
            is_active: this.formData.is_active,
        };

        this.http.post<any>(apiUrl, createData).subscribe({
            next: () => {
                this.showSuccessMessage('Line created successfully');
                this.closeModal();
                this.loadLines();
            },
            error: (error) => {
                console.error('Failed to create line:', error);
                this.showErrorMessage(error.error?.message || 'Failed to create line');
            },
        });
    }

    updateLine() {
        const apiUrl = `${environment.apiUrl}/v1/lines/${this.formData.id}`;

        const updateData = {
            call_server_id: this.formData.call_server_id,
            name: this.formData.name,
            line_number: this.formData.line_number,
            type: this.formData.type,
            channel_count: this.formData.channel_count,
            trunk_id: this.formData.trunk_id,
            description: this.formData.description,
            secret: this.formData.secret,
            is_active: this.formData.is_active,
        };

        this.http.put<any>(apiUrl, updateData).subscribe({
            next: () => {
                this.showSuccessMessage('Line updated successfully');
                this.closeModal();
                this.loadLines();
            },
            error: (error) => {
                console.error('Failed to update line:', error);
                this.showErrorMessage(error.error?.message || 'Failed to update line');
            },
        });
    }

    deleteLine(id: number) {
        Swal.fire({
            title: 'Are you sure?',
            text: 'You will not be able to recover this line!',
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#3085d6',
            cancelButtonColor: '#d33',
            confirmButtonText: 'Yes, delete it!',
            cancelButtonText: 'Cancel',
        }).then((result) => {
            if (result.isConfirmed) {
                const apiUrl = `${environment.apiUrl}/v1/lines/${id}`;

                this.http.delete<any>(apiUrl).subscribe({
                    next: () => {
                        this.showSuccessMessage('Line deleted successfully');
                        this.loadLines();
                    },
                    error: (error) => {
                        console.error('Failed to delete line:', error);
                        this.showErrorMessage(error.error?.message || 'Failed to delete line');
                    },
                });
            }
        });
    }

    showSuccessMessage(message: string) {
        Swal.fire({
            icon: 'success',
            title: 'Success',
            text: message,
            timer: 2000,
            showConfirmButton: false,
        });
    }

    showErrorMessage(message: string) {
        Swal.fire({
            icon: 'error',
            title: 'Error',
            text: message,
        });
    }
}
