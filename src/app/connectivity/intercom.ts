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
import { IconXCircleComponent } from '../shared/icon/icon-x-circle';
import { IconCopyComponent } from '../shared/icon/icon-copy';
import Swal from 'sweetalert2';

interface Intercom {
    id?: number;
    call_server_id: number | null;
    call_server?: { id: number; name: string };
    name: string;
    extension: string;
    description: string;
    device_list: string;
    alert_info: string;
    disabled: boolean;
}

interface CallServer { id: number; name: string; }

@Component({
    templateUrl: './intercom.html',
    animations: [toggleAnimation],
    imports: [CommonModule, FormsModule, RouterModule, IconPlusComponent, IconPencilComponent, IconTrashLinesComponent, IconCircleCheckComponent, IconXCircleComponent, IconCopyComponent],
})
export class IntercomComponent implements OnInit {
    store: any;
    intercoms: Intercom[] = [];
    callServers: CallServer[] = [];
    isLoading = false;
    search = '';
    showModal = false;
    modalMode: 'create' | 'edit' | 'view' = 'create';

    formData: Intercom = { call_server_id: null, name: '', extension: '', description: '', device_list: '', alert_info: 'Intercom', disabled: false };

    private http = inject(HttpClient);

    constructor(public storeData: Store<any>, public router: Router) {
        this.initStore();
    }

    async initStore() { this.storeData.select((d) => d.index).subscribe((d) => { this.store = d; }); }

    ngOnInit() { this.loadIntercoms(); this.loadCallServers(); }

    loadIntercoms() {
        this.isLoading = true;
        this.http.get<any>(`${environment.apiUrl}/v1/intercoms`).subscribe({
            next: (response) => { this.intercoms = response.data || []; this.isLoading = false; },
            error: (error) => { console.error('Failed to load intercoms:', error); this.isLoading = false; this.showErrorMessage('Failed to load intercoms'); },
        });
    }

    loadCallServers() {
        this.http.get<any>(`${environment.apiUrl}/v1/call-servers`).subscribe({
            next: (response) => { this.callServers = response.data || []; },
            error: (error) => { console.error('Failed to load call servers:', error); },
        });
    }

    openCreateModal() { this.modalMode = 'create'; this.resetForm(); this.showModal = true; }
    openEditModal(intercom: Intercom) { this.modalMode = 'edit'; this.formData = { ...intercom }; this.showModal = true; }
    copyRecord(intercom: Intercom) { this.modalMode = 'create'; this.formData = { ...intercom, id: undefined, name: intercom.name + ' - New' }; this.showModal = true; }
    closeModal() { this.showModal = false; this.resetForm(); }
    resetForm() { this.formData = { call_server_id: null, name: '', extension: '', description: '', device_list: '', alert_info: 'Intercom', disabled: false }; }

    handleSubmit() {
        if (this.modalMode === 'create') { this.createIntercom(); }
        else if (this.modalMode === 'edit') { this.updateIntercom(); }
    }

    createIntercom() {
        const createData = { call_server_id: this.formData.call_server_id, name: this.formData.name, extension: this.formData.extension, description: this.formData.description, device_list: this.formData.device_list, alert_info: this.formData.alert_info, disabled: this.formData.disabled };
        this.http.post<any>(`${environment.apiUrl}/v1/intercoms`, createData).subscribe({
            next: () => { this.showSuccessMessage('Intercom created successfully'); this.closeModal(); this.loadIntercoms(); },
            error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to create intercom'); },
        });
    }

    updateIntercom() {
        const updateData = { call_server_id: this.formData.call_server_id, name: this.formData.name, extension: this.formData.extension, description: this.formData.description, device_list: this.formData.device_list, alert_info: this.formData.alert_info, disabled: this.formData.disabled };
        this.http.put<any>(`${environment.apiUrl}/v1/intercoms/${this.formData.id}`, updateData).subscribe({
            next: () => { this.showSuccessMessage('Intercom updated successfully'); this.closeModal(); this.loadIntercoms(); },
            error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to update intercom'); },
        });
    }

    deleteIntercom(id: number) {
        Swal.fire({ title: 'Are you sure?', text: 'You will not be able to recover this intercom!', icon: 'warning', showCancelButton: true, confirmButtonColor: '#3085d6', cancelButtonColor: '#d33', confirmButtonText: 'Yes, delete it!' }).then((result) => {
            if (result.isConfirmed) {
                this.http.delete<any>(`${environment.apiUrl}/v1/intercoms/${id}`).subscribe({
                    next: () => { this.showSuccessMessage('Intercom deleted successfully'); this.loadIntercoms(); },
                    error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to delete intercom'); },
                });
            }
        });
    }

    showSuccessMessage(msg: string) { Swal.fire({ icon: 'success', title: 'Success', text: msg, timer: 2000, showConfirmButton: false }); }
    showErrorMessage(msg: string) { Swal.fire({ icon: 'error', title: 'Error', text: msg }); }
}
