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

interface CAS {
    id?: number;
    call_server_id: number | null;
    call_server?: { id: number; name: string };
    cas_number: string;
    destination_local: boolean;
    destination: string | null;
    is_active: boolean;
}

interface CallServer { id: number; name: string; }

@Component({
    templateUrl: './cas.html',
    animations: [toggleAnimation],
    imports: [CommonModule, FormsModule, RouterModule, IconPlusComponent, IconPencilComponent, IconTrashLinesComponent, IconCircleCheckComponent, IconXCircleComponent, IconCopyComponent],
})
export class CASComponent implements OnInit {
    store: any;
    casList: CAS[] = [];
    callServers: CallServer[] = [];
    isLoading = false;
    search = '';
    showModal = false;
    modalMode: 'create' | 'edit' | 'view' = 'create';

    formData: CAS = { call_server_id: null, cas_number: '', destination_local: false, destination: null, is_active: true };

    private http = inject(HttpClient);

    constructor(public storeData: Store<any>, public router: Router) {
        this.initStore();
    }

    async initStore() { this.storeData.select((d) => d.index).subscribe((d) => { this.store = d; }); }

    ngOnInit() { this.loadCAS(); this.loadCallServers(); }

    loadCAS() {
        this.isLoading = true;
        this.http.get<any>(`${environment.apiUrl}/v1/cas`).subscribe({
            next: (response) => { this.casList = response.data || []; this.isLoading = false; },
            error: (error) => { console.error('Failed to load CAS:', error); this.isLoading = false; this.showErrorMessage('Failed to load CAS'); },
        });
    }

    loadCallServers() {
        this.http.get<any>(`${environment.apiUrl}/v1/call-servers`).subscribe({
            next: (response) => { this.callServers = response.data || []; },
            error: (error) => { console.error('Failed to load call servers:', error); },
        });
    }

    openCreateModal() { this.modalMode = 'create'; this.resetForm(); this.showModal = true; }
    openEditModal(cas: CAS) { this.modalMode = 'edit'; this.formData = { ...cas }; this.showModal = true; }
    copyRecord(cas: CAS) { this.modalMode = 'create'; this.formData = { ...cas, id: undefined, cas_number: cas.cas_number + '-new' }; this.showModal = true; }
    closeModal() { this.showModal = false; this.resetForm(); }
    resetForm() { this.formData = { call_server_id: null, cas_number: '', destination_local: false, destination: null, is_active: true }; }

    handleSubmit() {
        if (this.modalMode === 'create') { this.createCAS(); }
        else if (this.modalMode === 'edit') { this.updateCAS(); }
    }

    createCAS() {
        const createData = { call_server_id: this.formData.call_server_id, cas_number: this.formData.cas_number, destination_local: this.formData.destination_local, destination: this.formData.destination, is_active: this.formData.is_active };
        this.http.post<any>(`${environment.apiUrl}/v1/cas`, createData).subscribe({
            next: () => {
                // Auto-create Private Wire
                const pwData = {
                    call_server_id: this.formData.call_server_id,
                    name: `CAS - ${this.formData.cas_number}`,
                    number: this.formData.cas_number,
                    destination: this.formData.destination,
                    description: 'Auto-created from CAS',
                    is_active: this.formData.is_active
                };
                this.http.post(`${environment.apiUrl}/v1/private-wires`, pwData).subscribe({
                    error: (err) => console.error('Failed to auto-create Private Wire:', err)
                });

                this.showSuccessMessage('CAS created successfully');
                this.closeModal();
                this.loadCAS();
            },
            error: (error) => { console.error('Failed to create CAS:', error); this.showErrorMessage(error.error?.error || 'Failed to create CAS'); },
        });
    }

    updateCAS() {
        const updateData = { call_server_id: this.formData.call_server_id, cas_number: this.formData.cas_number, destination_local: this.formData.destination_local, destination: this.formData.destination, is_active: this.formData.is_active };
        this.http.put<any>(`${environment.apiUrl}/v1/cas/${this.formData.id}`, updateData).subscribe({
            next: () => { this.showSuccessMessage('CAS updated successfully'); this.closeModal(); this.loadCAS(); },
            error: (error) => { console.error('Failed to update CAS:', error); this.showErrorMessage(error.error?.error || 'Failed to update CAS'); },
        });
    }

    deleteCAS(id: number) {
        Swal.fire({ title: 'Are you sure?', text: 'You will not be able to recover this CAS!', icon: 'warning', showCancelButton: true, confirmButtonColor: '#3085d6', cancelButtonColor: '#d33', confirmButtonText: 'Yes, delete it!' }).then((result) => {
            if (result.isConfirmed) {
                this.http.delete<any>(`${environment.apiUrl}/v1/cas/${id}`).subscribe({
                    next: () => { this.showSuccessMessage('CAS deleted successfully'); this.loadCAS(); },
                    error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to delete CAS'); },
                });
            }
        });
    }

    showSuccessMessage(msg: string) { Swal.fire({ icon: 'success', title: 'Success', text: msg, timer: 2000, showConfirmButton: false }); }
    showErrorMessage(msg: string) { Swal.fire({ icon: 'error', title: 'Error', text: msg }); }
}
