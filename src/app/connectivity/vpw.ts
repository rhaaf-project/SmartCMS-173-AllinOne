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

interface VPW {
    id?: number;
    call_server_id: number | null;
    call_server?: { id: number; name: string };
    number: string;
    destination_local: boolean;
    destination: string | null;
    is_active: boolean;
}

interface CallServer { id: number; name: string; }

@Component({
    templateUrl: './vpw.html',
    animations: [toggleAnimation],
    imports: [CommonModule, FormsModule, RouterModule, IconPlusComponent, IconPencilComponent, IconTrashLinesComponent, IconCircleCheckComponent, IconXCircleComponent, IconCopyComponent],
})
export class VPWComponent implements OnInit {
    store: any;
    vpws: VPW[] = [];
    callServers: CallServer[] = [];
    isLoading = false;
    search = '';
    showModal = false;
    modalMode: 'create' | 'edit' | 'view' = 'create';

    formData: VPW = { call_server_id: null, number: '', destination_local: false, destination: null, is_active: true };

    private http = inject(HttpClient);

    constructor(public storeData: Store<any>, public router: Router) {
        this.initStore();
    }

    async initStore() { this.storeData.select((d) => d.index).subscribe((d) => { this.store = d; }); }

    ngOnInit() { this.loadVPWs(); this.loadCallServers(); }

    loadVPWs() {
        this.isLoading = true;
        this.http.get<any>(`${environment.apiUrl}/v1/vpws`).subscribe({
            next: (response) => { this.vpws = response.data || []; this.isLoading = false; },
            error: (error) => { console.error('Failed to load VPWs:', error); this.isLoading = false; this.showErrorMessage('Failed to load VPWs'); },
        });
    }

    loadCallServers() {
        this.http.get<any>(`${environment.apiUrl}/v1/call-servers`).subscribe({
            next: (response) => { this.callServers = response.data || []; },
            error: (error) => { console.error('Failed to load call servers:', error); },
        });
    }

    openCreateModal() { this.modalMode = 'create'; this.resetForm(); this.showModal = true; }
    openEditModal(vpw: VPW) { this.modalMode = 'edit'; this.formData = { ...vpw }; this.showModal = true; }
    copyRecord(vpw: VPW) { this.modalMode = 'create'; this.formData = { ...vpw, id: undefined, number: vpw.number + '-new' }; this.showModal = true; }
    closeModal() { this.showModal = false; this.resetForm(); }
    resetForm() { this.formData = { call_server_id: null, number: '', destination_local: false, destination: null, is_active: true }; }

    handleSubmit() {
        if (this.modalMode === 'create') { this.createVPW(); }
        else if (this.modalMode === 'edit') { this.updateVPW(); }
    }

    createVPW() {
        const createData = {
            call_server_id: this.formData.call_server_id,
            name: `VPW - ${this.formData.number}`,
            number: this.formData.number,
            destination: this.formData.destination,
            description: 'Created from VPW interface',
            is_active: this.formData.is_active
        };

        this.http.post<any>(`${environment.apiUrl}/v1/vpws`, createData).subscribe({
            next: () => {
                this.showSuccessMessage('VPW created successfully');
                this.closeModal();
                this.loadVPWs();
            },
            error: (error) => { console.error('Failed to create VPW:', error); this.showErrorMessage(error.error?.error || 'Failed to create VPW'); },
        });
    }

    updateVPW() {
        const updateData = {
            call_server_id: this.formData.call_server_id,
            name: `VPW - ${this.formData.number}`,
            number: this.formData.number,
            destination: this.formData.destination,
            is_active: this.formData.is_active
        };
        this.http.put<any>(`${environment.apiUrl}/v1/vpws/${this.formData.id}`, updateData).subscribe({
            next: () => { this.showSuccessMessage('VPW updated successfully'); this.closeModal(); this.loadVPWs(); },
            error: (error) => { console.error('Failed to update VPW:', error); this.showErrorMessage(error.error?.error || 'Failed to update VPW'); },
        });
    }

    deleteVPW(id: number) {
        Swal.fire({ title: 'Are you sure?', text: 'You will not be able to recover this VPW!', icon: 'warning', showCancelButton: true, confirmButtonColor: '#3085d6', cancelButtonColor: '#d33', confirmButtonText: 'Yes, delete it!' }).then((result) => {
            if (result.isConfirmed) {
                this.http.delete<any>(`${environment.apiUrl}/v1/vpws/${id}`).subscribe({
                    next: () => { this.showSuccessMessage('VPW deleted successfully'); this.loadVPWs(); },
                    error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to delete VPW'); },
                });
            }
        });
    }

    showSuccessMessage(msg: string) { Swal.fire({ icon: 'success', title: 'Success', text: msg, timer: 2000, showConfirmButton: false }); }
    showErrorMessage(msg: string) { Swal.fire({ icon: 'error', title: 'Error', text: msg }); }
}
