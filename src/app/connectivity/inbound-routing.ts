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

interface InboundRouting {
    id?: number;
    call_server_id: number | null;
    call_server?: { id: number; name: string };
    name: string;
    did_number: string | null;
    destination: string | null;
    destination_type: string | null;
    description: string | null;
    is_active: boolean;
}

interface CallServer { id: number; name: string; }

@Component({
    templateUrl: './inbound-routing.html',
    animations: [toggleAnimation],
    imports: [CommonModule, FormsModule, RouterModule, IconPlusComponent, IconPencilComponent, IconTrashLinesComponent, IconCircleCheckComponent, IconCopyComponent],
})
export class InboundRoutingComponent implements OnInit {
    store: any;
    routes: InboundRouting[] = [];
    callServers: CallServer[] = [];
    isLoading = false;
    search = '';
    showModal = false;
    modalMode: 'create' | 'edit' | 'view' = 'create';

    destinationTypes = [
        { value: 'extension', label: 'Extension' },
        { value: 'ring_group', label: 'Ring Group' },
        { value: 'ivr', label: 'IVR' },
        { value: 'queue', label: 'Queue' },
        { value: 'voicemail', label: 'Voicemail' },
    ];

    formData: InboundRouting = { call_server_id: null, name: '', did_number: null, destination: null, destination_type: null, description: null, is_active: true };

    private http = inject(HttpClient);

    constructor(public storeData: Store<any>, public router: Router) {
        this.initStore();
    }

    async initStore() { this.storeData.select((d) => d.index).subscribe((d) => { this.store = d; }); }

    ngOnInit() { this.loadRoutes(); this.loadCallServers(); }

    loadRoutes() {
        this.isLoading = true;
        this.http.get<any>(`${environment.apiUrl}/v1/inbound-routings`).subscribe({
            next: (response) => { this.routes = response.data || []; this.isLoading = false; },
            error: (error) => { console.error('Failed to load routes:', error); this.isLoading = false; this.showErrorMessage('Failed to load routes'); },
        });
    }

    loadCallServers() {
        this.http.get<any>(`${environment.apiUrl}/v1/call-servers`).subscribe({
            next: (response) => { this.callServers = response.data || []; },
            error: (error) => { console.error('Failed to load call servers:', error); },
        });
    }

    openCreateModal() { this.modalMode = 'create'; this.resetForm(); this.showModal = true; }
    openEditModal(route: InboundRouting) { this.modalMode = 'edit'; this.formData = { ...route }; this.showModal = true; }
    copyRecord(route: InboundRouting) { this.modalMode = 'create'; this.formData = { ...route, id: undefined, name: route.name + ' - New' }; this.showModal = true; }
    closeModal() { this.showModal = false; this.resetForm(); }
    resetForm() { this.formData = { call_server_id: null, name: '', did_number: null, destination: null, destination_type: null, description: null, is_active: true }; }

    handleSubmit() {
        if (this.modalMode === 'create') { this.createRoute(); }
        else if (this.modalMode === 'edit') { this.updateRoute(); }
    }

    createRoute() {
        const createData = { call_server_id: this.formData.call_server_id, name: this.formData.name, did_number: this.formData.did_number, destination: this.formData.destination, destination_type: this.formData.destination_type, description: this.formData.description, is_active: this.formData.is_active };
        this.http.post<any>(`${environment.apiUrl}/v1/inbound-routings`, createData).subscribe({
            next: () => { this.showSuccessMessage('Route created successfully'); this.closeModal(); this.loadRoutes(); },
            error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to create route'); },
        });
    }

    updateRoute() {
        const updateData = { call_server_id: this.formData.call_server_id, name: this.formData.name, did_number: this.formData.did_number, destination: this.formData.destination, destination_type: this.formData.destination_type, description: this.formData.description, is_active: this.formData.is_active };
        this.http.put<any>(`${environment.apiUrl}/v1/inbound-routings/${this.formData.id}`, updateData).subscribe({
            next: () => { this.showSuccessMessage('Route updated successfully'); this.closeModal(); this.loadRoutes(); },
            error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to update route'); },
        });
    }

    deleteRoute(id: number) {
        Swal.fire({ title: 'Are you sure?', text: 'You will not be able to recover this route!', icon: 'warning', showCancelButton: true, confirmButtonColor: '#3085d6', cancelButtonColor: '#d33', confirmButtonText: 'Yes, delete it!' }).then((result) => {
            if (result.isConfirmed) {
                this.http.delete<any>(`${environment.apiUrl}/v1/inbound-routings/${id}`).subscribe({
                    next: () => { this.showSuccessMessage('Route deleted successfully'); this.loadRoutes(); },
                    error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to delete route'); },
                });
            }
        });
    }

    showSuccessMessage(msg: string) { Swal.fire({ icon: 'success', title: 'Success', text: msg, timer: 2000, showConfirmButton: false }); }
    showErrorMessage(msg: string) { Swal.fire({ icon: 'error', title: 'Error', text: msg }); }
}
