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

interface Trunk {
    id?: number;
    call_server_id: number | null;
    call_server?: { id: number; name: string };
    name: string;
    sip_server: string;
    sip_server_port: number;
    outcid: string | null;
    maxchans: number;
    transport: string;
    context: string;
    disabled: boolean;
}

interface CallServer { id: number; name: string; }

@Component({
    templateUrl: './trunk.html',
    animations: [toggleAnimation],
    imports: [CommonModule, FormsModule, RouterModule, IconPlusComponent, IconPencilComponent, IconTrashLinesComponent, IconCircleCheckComponent, IconXCircleComponent, IconCopyComponent],
})
export class TrunkComponent implements OnInit {
    store: any;
    trunks: Trunk[] = [];
    callServers: CallServer[] = [];
    isLoading = false;
    search = '';
    showModal = false;
    modalMode: 'create' | 'edit' | 'view' = 'create';

    transportOptions = [{ value: 'udp', label: 'UDP' }, { value: 'tcp', label: 'TCP' }, { value: 'tls', label: 'TLS' }];

    formData: Trunk = { call_server_id: null, name: '', sip_server: '', sip_server_port: 5060, outcid: null, maxchans: 2, transport: 'udp', context: 'from-pstn', disabled: false };

    private http = inject(HttpClient);

    constructor(public storeData: Store<any>, public router: Router) {
        this.initStore();
    }

    async initStore() { this.storeData.select((d) => d.index).subscribe((d) => { this.store = d; }); }

    ngOnInit() { this.loadTrunks(); this.loadCallServers(); }

    loadTrunks() {
        this.isLoading = true;
        this.http.get<any>(`${environment.apiUrl}/v1/trunks`).subscribe({
            next: (response) => { this.trunks = response.data || []; this.isLoading = false; },
            error: (error) => { console.error('Failed to load trunks:', error); this.isLoading = false; this.showErrorMessage('Failed to load trunks'); },
        });
    }

    loadCallServers() {
        this.http.get<any>(`${environment.apiUrl}/v1/call-servers`).subscribe({
            next: (response) => { this.callServers = response.data || []; },
            error: (error) => { console.error('Failed to load call servers:', error); },
        });
    }

    openCreateModal() { this.modalMode = 'create'; this.resetForm(); this.showModal = true; }
    openEditModal(trunk: Trunk) { this.modalMode = 'edit'; this.formData = { ...trunk }; this.showModal = true; }
    copyRecord(trunk: Trunk) { this.modalMode = 'create'; this.formData = { ...trunk, id: undefined, name: trunk.name + ' - New' }; this.showModal = true; }
    closeModal() { this.showModal = false; this.resetForm(); }
    resetForm() { this.formData = { call_server_id: null, name: '', sip_server: '', sip_server_port: 5060, outcid: null, maxchans: 2, transport: 'udp', context: 'from-pstn', disabled: false }; }

    handleSubmit() {
        if (this.modalMode === 'create') { this.createTrunk(); }
        else if (this.modalMode === 'edit') { this.updateTrunk(); }
    }

    createTrunk() {
        const createData = { call_server_id: this.formData.call_server_id, name: this.formData.name, sip_server: this.formData.sip_server, sip_server_port: this.formData.sip_server_port, outcid: this.formData.outcid, maxchans: this.formData.maxchans, transport: this.formData.transport, context: this.formData.context, disabled: this.formData.disabled };
        this.http.post<any>(`${environment.apiUrl}/v1/trunks`, createData).subscribe({
            next: () => { this.showSuccessMessage('Trunk created successfully'); this.closeModal(); this.loadTrunks(); },
            error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to create trunk'); },
        });
    }

    updateTrunk() {
        const updateData = { call_server_id: this.formData.call_server_id, name: this.formData.name, sip_server: this.formData.sip_server, sip_server_port: this.formData.sip_server_port, outcid: this.formData.outcid, maxchans: this.formData.maxchans, transport: this.formData.transport, context: this.formData.context, disabled: this.formData.disabled };
        this.http.put<any>(`${environment.apiUrl}/v1/trunks/${this.formData.id}`, updateData).subscribe({
            next: () => { this.showSuccessMessage('Trunk updated successfully'); this.closeModal(); this.loadTrunks(); },
            error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to update trunk'); },
        });
    }

    deleteTrunk(id: number) {
        Swal.fire({ title: 'Are you sure?', text: 'You will not be able to recover this trunk!', icon: 'warning', showCancelButton: true, confirmButtonColor: '#3085d6', cancelButtonColor: '#d33', confirmButtonText: 'Yes, delete it!' }).then((result) => {
            if (result.isConfirmed) {
                this.http.delete<any>(`${environment.apiUrl}/v1/trunks/${id}`).subscribe({
                    next: () => { this.showSuccessMessage('Trunk deleted successfully'); this.loadTrunks(); },
                    error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to delete trunk'); },
                });
            }
        });
    }

    showSuccessMessage(msg: string) { Swal.fire({ icon: 'success', title: 'Success', text: msg, timer: 2000, showConfirmButton: false }); }
    showErrorMessage(msg: string) { Swal.fire({ icon: 'error', title: 'Error', text: msg }); }
}
