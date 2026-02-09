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
import { IconEyeComponent } from '../shared/icon/icon-eye';
import { IconCircleCheckComponent } from '../shared/icon/icon-circle-check';
import { IconCopyComponent } from '../shared/icon/icon-copy';
import Swal from 'sweetalert2';

interface CallServer {
    id?: number;
    head_office_id: number | null;
    head_office?: {
        id: number;
        name: string;
    };
    name: string;
    host: string;
    port: number;
    is_active: boolean;
    description: string | null;
    created_at?: string;
    updated_at?: string;
    // Mock stats
    ext_count?: number;
    lines_count?: number;
    trunks_count?: number;
}

interface HeadOffice {
    id: number;
    name: string;
    customer_id: number;
    type: string;
}

@Component({
    templateUrl: './call-servers.html',
    animations: [toggleAnimation],
    imports: [
        CommonModule,
        FormsModule,
        RouterModule,
        IconPlusComponent,
        IconPencilComponent,
        IconTrashLinesComponent,
        IconEyeComponent,
        IconCircleCheckComponent,
        IconCopyComponent,
    ],
})
export class CallServersComponent implements OnInit {
    store: any;
    callServers: CallServer[] = [];
    headOffices: HeadOffice[] = [];
    isLoading = false;
    search = '';
    showModal = false;
    modalMode: 'create' | 'edit' | 'view' = 'create';

    // Report View
    showReportModal = false;
    reportData: CallServer | null = null;
    reportGeneratedDate: Date = new Date();

    formData: CallServer = {
        head_office_id: null,
        name: '',
        host: '',
        port: 5060,
        is_active: true,
        description: null,
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
        this.loadCallServers();
        this.loadHeadOffices();
    }

    loadCallServers() {
        this.isLoading = true;
        const apiUrl = `${environment.apiUrl}/v1/call-servers`;

        this.http.get<any>(apiUrl).subscribe({
            next: (response) => {
                this.callServers = response.data || [];
                this.isLoading = false;
            },
            error: (error) => {
                console.error('Failed to load call servers:', error);
                this.isLoading = false;
                this.showErrorMessage('Failed to load call servers');
            },
        });
    }

    loadHeadOffices() {
        const apiUrl = `${environment.apiUrl}/v1/head-offices`;

        this.http.get<any>(apiUrl).subscribe({
            next: (response) => {
                this.headOffices = response.data || [];
            },
            error: (error) => {
                console.error('Failed to load head offices:', error);
            },
        });
    }

    openCreateModal() {
        this.modalMode = 'create';
        this.resetForm();
        this.showModal = true;
    }

    openEditModal(callServer: CallServer) {
        this.modalMode = 'edit';
        this.formData = { ...callServer };
        this.showModal = true;
    }

    openViewModal(callServer: CallServer) {
        this.modalMode = 'view';
        this.formData = { ...callServer };
        this.showModal = true;
    }

    copyRecord(callServer: CallServer) {
        this.modalMode = 'create';
        this.formData = { ...callServer, id: undefined, name: callServer.name + ' - Copy' };
        this.showModal = true;
    }

    closeModal() {
        this.showModal = false;
        this.resetForm();
    }

    // Report View Functions
    openReportView(callServer: CallServer) {
        this.reportData = { ...callServer };
        this.reportGeneratedDate = new Date();
        this.showReportModal = true;
    }

    closeReportModal() {
        this.showReportModal = false;
        this.reportData = null;
    }

    printReport() {
        window.print();
    }

    resetForm() {
        this.formData = {
            head_office_id: null,
            name: '',
            host: '',
            port: 5060,
            is_active: true,
            description: null,
        };
    }

    handleSubmit() {
        if (this.modalMode === 'create') {
            this.createCallServer();
        } else if (this.modalMode === 'edit') {
            this.updateCallServer();
        }
    }

    createCallServer() {
        const apiUrl = `${environment.apiUrl}/v1/call-servers`;

        // Only send valid database fields, exclude relation objects
        const createData = {
            head_office_id: this.formData.head_office_id,
            name: this.formData.name,
            host: this.formData.host,
            port: this.formData.port,
            is_active: this.formData.is_active,
            description: this.formData.description,
        };

        this.http.post<any>(apiUrl, createData).subscribe({
            next: (response) => {
                this.showSuccessMessage('Call server created successfully');
                this.closeModal();
                this.loadCallServers();
            },
            error: (error) => {
                console.error('Failed to create call server:', error);
                this.showErrorMessage(error.error?.message || 'Failed to create call server');
            },
        });
    }

    updateCallServer() {
        const apiUrl = `${environment.apiUrl}/v1/call-servers/${this.formData.id}`;

        // Only send valid database fields
        const updateData = {
            head_office_id: this.formData.head_office_id,
            name: this.formData.name,
            host: this.formData.host,
            port: this.formData.port,
            is_active: this.formData.is_active,
            description: this.formData.description,
        };

        this.http.put<any>(apiUrl, updateData).subscribe({
            next: (response) => {
                this.showSuccessMessage('Call server updated successfully');
                this.closeModal();
                this.loadCallServers();
            },
            error: (error) => {
                console.error('Failed to update call server:', error);
                this.showErrorMessage(error.error?.message || 'Failed to update call server');
            },
        });
    }

    deleteCallServer(id: number) {
        Swal.fire({
            title: 'Are you sure?',
            text: 'You will not be able to recover this call server!',
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#3085d6',
            cancelButtonColor: '#d33',
            confirmButtonText: 'Yes, delete it!',
            cancelButtonText: 'Cancel',
        }).then((result) => {
            if (result.isConfirmed) {
                const apiUrl = `${environment.apiUrl}/v1/call-servers/${id}`;

                this.http.delete<any>(apiUrl).subscribe({
                    next: (response) => {
                        this.showSuccessMessage('Call server deleted successfully');
                        this.loadCallServers();
                    },
                    error: (error) => {
                        console.error('Failed to delete call server:', error);
                        this.showErrorMessage(error.error?.message || 'Failed to delete call server');
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
