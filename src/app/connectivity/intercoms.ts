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
import { IconCopyComponent } from '../shared/icon/icon-copy';
import Swal from 'sweetalert2';

interface Intercom {
    id?: number;
    call_server_id: number;
    branch_id: number | null;
    call_server?: {
        id: number;
        name: string;
    };
    branch?: {
        id: number;
        name: string;
    };
    name: string;
    extension: string;
    description: string | null;
    is_active: boolean;
    created_at?: string;
    updated_at?: string;
}

interface CallServer {
    id: number;
    name: string;
    host: string;
}



@Component({
    selector: 'app-intercoms',
    standalone: true,
    templateUrl: './intercoms.html',
    animations: [toggleAnimation],
    imports: [
        CommonModule,
        FormsModule,
        RouterModule,
        IconPlusComponent,
        IconPencilComponent,
        IconTrashLinesComponent,
        IconCopyComponent,
    ],
})
export class IntercomsComponent implements OnInit {
    store: any;
    intercoms: Intercom[] = [];
    callServers: CallServer[] = [];
    isLoading = false;
    showModal = false;
    modalMode: 'create' | 'edit' | 'view' = 'create';

    formData: Intercom = {
        call_server_id: 0,
        branch_id: null,
        name: '',
        extension: '',
        description: null,
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
        this.loadIntercoms();
        this.loadCallServers();
    }

    loadIntercoms() {
        this.isLoading = true;
        const apiUrl = `${environment.apiUrl}/v1/intercoms`;

        this.http.get<any>(apiUrl).subscribe({
            next: (response) => {
                this.intercoms = response.data || [];
                this.isLoading = false;
            },
            error: (error) => {
                console.error('Failed to load intercoms:', error);
                this.isLoading = false;
                this.showErrorMessage('Failed to load intercoms');
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

    openEditModal(intercom: Intercom) {
        this.modalMode = 'edit';
        this.formData = { ...intercom };
        this.showModal = true;
    }

    copyRecord(intercom: Intercom) {
        this.modalMode = 'create';
        this.formData = {
            ...intercom,
            id: undefined,
            name: intercom.name + ' (Copy)',
        };
        this.showModal = true;
    }

    closeModal() {
        this.showModal = false;
        this.resetForm();
    }

    resetForm() {
        this.formData = {
            call_server_id: 0,
            branch_id: null,
            name: '',
            extension: '',
            description: null,
            is_active: true,
        };
    }

    handleSubmit() {
        if (this.modalMode === 'create') {
            this.createIntercom();
        } else if (this.modalMode === 'edit') {
            this.updateIntercom();
        }
    }

    createIntercom() {
        const apiUrl = `${environment.apiUrl}/v1/intercoms`;

        this.http.post<any>(apiUrl, this.formData).subscribe({
            next: (response) => {
                this.showSuccessMessage('Intercom created successfully');
                this.closeModal();
                this.loadIntercoms();
            },
            error: (error) => {
                console.error('Failed to create intercom:', error);
                this.showErrorMessage(error.error?.message || 'Failed to create intercom');
            },
        });
    }

    updateIntercom() {
        const apiUrl = `${environment.apiUrl}/v1/intercoms/${this.formData.id}`;

        this.http.put<any>(apiUrl, this.formData).subscribe({
            next: (response) => {
                this.showSuccessMessage('Intercom updated successfully');
                this.closeModal();
                this.loadIntercoms();
            },
            error: (error) => {
                console.error('Failed to update intercom:', error);
                this.showErrorMessage(error.error?.message || 'Failed to update intercom');
            },
        });
    }

    deleteIntercom(id: number) {
        Swal.fire({
            title: 'Are you sure?',
            text: 'You will not be able to recover this intercom!',
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#3085d6',
            cancelButtonColor: '#d33',
            confirmButtonText: 'Yes, delete it!',
            cancelButtonText: 'Cancel',
        }).then((result) => {
            if (result.isConfirmed) {
                const apiUrl = `${environment.apiUrl}/v1/intercoms/${id}`;

                this.http.delete<any>(apiUrl).subscribe({
                    next: (response) => {
                        this.showSuccessMessage('Intercom deleted successfully');
                        this.loadIntercoms();
                    },
                    error: (error) => {
                        console.error('Failed to delete intercom:', error);
                        this.showErrorMessage(error.error?.message || 'Failed to delete intercom');
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
