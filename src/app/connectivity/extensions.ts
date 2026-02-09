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

interface Extension {
    id?: number;
    call_server_id: number | null;
    call_server?: { id: number; name: string };
    extension: string;
    name: string;
    secret: string | null;
    context: string;
    description: string | null;
    is_active: boolean;
    created_at?: string;
    updated_at?: string;
}

interface CallServer {
    id: number;
    name: string;
}

@Component({
    templateUrl: './extensions.html',
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
export class ExtensionsComponent implements OnInit {
    store: any;
    extensions: Extension[] = [];
    callServers: CallServer[] = [];
    isLoading = false;
    search = '';
    showModal = false;
    modalMode: 'create' | 'edit' | 'view' = 'create';

    formData: Extension = {
        call_server_id: null,
        extension: '',
        name: '',
        secret: null,
        context: 'from-internal',
        description: null,
        is_active: true,
    };

    private http = inject(HttpClient);

    constructor(public storeData: Store<any>, public router: Router) {
        this.initStore();
    }

    async initStore() {
        this.storeData.select((d) => d.index).subscribe((d) => { this.store = d; });
    }

    ngOnInit() {
        this.loadExtensions();
        this.loadCallServers();
    }

    loadExtensions() {
        this.isLoading = true;
        this.http.get<any>(`${environment.apiUrl}/v1/extensions`).subscribe({
            next: (response) => { this.extensions = response.data || []; this.isLoading = false; },
            error: (error) => { console.error('Failed to load extensions:', error); this.isLoading = false; this.showErrorMessage('Failed to load extensions'); },
        });
    }

    loadCallServers() {
        this.http.get<any>(`${environment.apiUrl}/v1/call-servers`).subscribe({
            next: (response) => { this.callServers = response.data || []; },
            error: (error) => { console.error('Failed to load call servers:', error); },
        });
    }

    openCreateModal() { this.modalMode = 'create'; this.resetForm(); this.showModal = true; }
    openEditModal(ext: Extension) { this.modalMode = 'edit'; this.formData = { ...ext }; this.showModal = true; }
    copyRecord(ext: Extension) { this.modalMode = 'create'; this.formData = { ...ext, id: undefined, name: ext.name + ' - New', extension: ext.extension + '-new' }; this.showModal = true; }
    closeModal() { this.showModal = false; this.resetForm(); }

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
            extension: '',
            name: '',
            secret: this.generateRandomSecret(),
            context: 'from-internal',
            description: null,
            is_active: true
        };
    }

    handleSubmit() {
        if (this.modalMode === 'create') { this.createExtension(); }
        else if (this.modalMode === 'edit') { this.updateExtension(); }
    }

    createExtension() {
        const createData = { call_server_id: this.formData.call_server_id, extension: this.formData.extension, name: this.formData.name, secret: this.formData.secret, context: this.formData.context, description: this.formData.description, is_active: this.formData.is_active };
        this.http.post<any>(`${environment.apiUrl}/v1/extensions`, createData).subscribe({
            next: () => { this.showSuccessMessage('Extension created successfully'); this.closeModal(); this.loadExtensions(); },
            error: (error) => { this.showErrorMessage(error.error?.message || 'Failed to create extension'); },
        });
    }

    updateExtension() {
        const updateData = { call_server_id: this.formData.call_server_id, extension: this.formData.extension, name: this.formData.name, secret: this.formData.secret, context: this.formData.context, description: this.formData.description, is_active: this.formData.is_active };
        this.http.put<any>(`${environment.apiUrl}/v1/extensions/${this.formData.id}`, updateData).subscribe({
            next: () => { this.showSuccessMessage('Extension updated successfully'); this.closeModal(); this.loadExtensions(); },
            error: (error) => { this.showErrorMessage(error.error?.message || 'Failed to update extension'); },
        });
    }

    deleteExtension(id: number) {
        Swal.fire({ title: 'Are you sure?', text: 'You will not be able to recover this extension!', icon: 'warning', showCancelButton: true, confirmButtonColor: '#3085d6', cancelButtonColor: '#d33', confirmButtonText: 'Yes, delete it!', cancelButtonText: 'Cancel' }).then((result) => {
            if (result.isConfirmed) {
                this.http.delete<any>(`${environment.apiUrl}/v1/extensions/${id}`).subscribe({
                    next: () => { this.showSuccessMessage('Extension deleted successfully'); this.loadExtensions(); },
                    error: (error) => { this.showErrorMessage(error.error?.message || 'Failed to delete extension'); },
                });
            }
        });
    }

    showSuccessMessage(msg: string) { Swal.fire({ icon: 'success', title: 'Success', text: msg, timer: 2000, showConfirmButton: false }); }
    showErrorMessage(msg: string) { Swal.fire({ icon: 'error', title: 'Error', text: msg }); }
}
