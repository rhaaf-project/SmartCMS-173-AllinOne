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

interface PrivateWire {
    id?: number;
    call_server_id: number | null;
    call_server?: { id: number; name: string };
    name: string;
    number: string | null;
    destination: string | null;
    description: string | null;
    is_active: boolean;
}

interface CallServer { id: number; name: string; }

@Component({
    templateUrl: './private-wire.html',
    animations: [toggleAnimation],
    imports: [CommonModule, FormsModule, RouterModule, IconPlusComponent, IconPencilComponent, IconTrashLinesComponent, IconCircleCheckComponent, IconXCircleComponent, IconCopyComponent],
})
export class PrivateWireComponent implements OnInit {
    store: any;
    privateWires: PrivateWire[] = [];
    callServers: CallServer[] = [];
    isLoading = false;
    search = '';
    showModal = false;
    modalMode: 'create' | 'edit' | 'view' = 'create';

    formData: PrivateWire = { call_server_id: null, name: '', number: null, destination: null, description: null, is_active: true };

    private http = inject(HttpClient);

    constructor(public storeData: Store<any>, public router: Router) {
        this.initStore();
    }

    async initStore() { this.storeData.select((d) => d.index).subscribe((d) => { this.store = d; }); }

    ngOnInit() { this.loadPrivateWires(); this.loadCallServers(); }

    loadPrivateWires() {
        this.isLoading = true;
        this.http.get<any>(`${environment.apiUrl}/v1/private-wires`).subscribe({
            next: (response) => { this.privateWires = response.data || []; this.isLoading = false; },
            error: (error) => { console.error('Failed to load private wires:', error); this.isLoading = false; this.showErrorMessage('Failed to load private wires'); },
        });
    }

    loadCallServers() {
        this.http.get<any>(`${environment.apiUrl}/v1/call-servers`).subscribe({
            next: (response) => { this.callServers = response.data || []; },
            error: (error) => { console.error('Failed to load call servers:', error); },
        });
    }

    openCreateModal() { this.modalMode = 'create'; this.resetForm(); this.showModal = true; }
    openEditModal(pw: PrivateWire) { this.modalMode = 'edit'; this.formData = { ...pw }; this.showModal = true; }
    copyRecord(pw: PrivateWire) { this.modalMode = 'create'; this.formData = { ...pw, id: undefined, name: pw.name + ' - New' }; this.showModal = true; }
    closeModal() { this.showModal = false; this.resetForm(); }
    resetForm() { this.formData = { call_server_id: null, name: '', number: null, destination: null, description: null, is_active: true }; }

    handleSubmit() {
        if (this.modalMode === 'create') { this.createPrivateWire(); }
        else if (this.modalMode === 'edit') { this.updatePrivateWire(); }
    }

    createPrivateWire() {
        const createData = { call_server_id: this.formData.call_server_id, name: this.formData.name, number: this.formData.number, destination: this.formData.destination, description: this.formData.description, is_active: this.formData.is_active };
        this.http.post<any>(`${environment.apiUrl}/v1/private-wires`, createData).subscribe({
            next: () => { this.showSuccessMessage('Private Wire created successfully'); this.closeModal(); this.loadPrivateWires(); },
            error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to create private wire'); },
        });
    }

    updatePrivateWire() {
        const updateData = { call_server_id: this.formData.call_server_id, name: this.formData.name, number: this.formData.number, destination: this.formData.destination, description: this.formData.description, is_active: this.formData.is_active };
        this.http.put<any>(`${environment.apiUrl}/v1/private-wires/${this.formData.id}`, updateData).subscribe({
            next: () => { this.showSuccessMessage('Private Wire updated successfully'); this.closeModal(); this.loadPrivateWires(); },
            error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to update private wire'); },
        });
    }

    deletePrivateWire(id: number) {
        Swal.fire({ title: 'Are you sure?', text: 'You will not be able to recover this private wire!', icon: 'warning', showCancelButton: true, confirmButtonColor: '#3085d6', cancelButtonColor: '#d33', confirmButtonText: 'Yes, delete it!' }).then((result) => {
            if (result.isConfirmed) {
                this.http.delete<any>(`${environment.apiUrl}/v1/private-wires/${id}`).subscribe({
                    next: () => { this.showSuccessMessage('Private Wire deleted successfully'); this.loadPrivateWires(); },
                    error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to delete private wire'); },
                });
            }
        });
    }

    showSuccessMessage(msg: string) { Swal.fire({ icon: 'success', title: 'Success', text: msg, timer: 2000, showConfirmButton: false }); }
    showErrorMessage(msg: string) { Swal.fire({ icon: 'error', title: 'Error', text: msg }); }
}
