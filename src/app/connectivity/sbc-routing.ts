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

interface SBCRoute {
    id?: number;
    // Source
    src_call_server_id: number | null;
    src_description: string | null;
    src_pattern: string;
    src_cid_filter: string | null;
    src_priority: number;
    src_is_active: boolean;
    src_from_sbc_id: number | null;
    src_destination_id: number | null;
    // Destination
    dest_call_server_id: number | null;
    dest_description: string | null;
    dest_pattern: string;
    dest_cid_filter: string | null;
    dest_priority: number;
    dest_is_active: boolean;
    dest_from_sbc_id: number | null;
    dest_destination_id: number | null;
    // Relations for display
    sbc?: { id: number; name: string };
}

interface CallServer { id: number; name: string; }
interface SBC { id: number; name: string; }
interface Trunk { id: number; name: string; }

@Component({
    templateUrl: './sbc-routing.html',
    animations: [toggleAnimation],
    imports: [CommonModule, FormsModule, RouterModule, IconPlusComponent, IconPencilComponent, IconTrashLinesComponent, IconCopyComponent],
})
export class SBCRoutingComponent implements OnInit {
    store: any;
    routes: SBCRoute[] = [];
    callServers: CallServer[] = [];
    sbcs: SBC[] = [];
    trunks: Trunk[] = [];
    isLoading = false;
    search = '';
    masterName = '';
    showModal = false;
    modalMode: 'create' | 'edit' | 'view' = 'create';

    formData: SBCRoute = {
        src_call_server_id: null, src_description: null, src_pattern: '', src_cid_filter: null, src_priority: 0, src_is_active: true, src_from_sbc_id: null, src_destination_id: null,
        dest_call_server_id: null, dest_description: null, dest_pattern: '', dest_cid_filter: null, dest_priority: 0, dest_is_active: true, dest_from_sbc_id: null, dest_destination_id: null,
    };

    private http = inject(HttpClient);

    constructor(public storeData: Store<any>, public router: Router) {
        this.initStore();
    }

    async initStore() { this.storeData.select((d) => d.index).subscribe((d) => { this.store = d; }); }

    ngOnInit() { this.loadRoutes(); this.loadCallServers(); this.loadSBCs(); this.loadTrunks(); }

    loadRoutes() {
        this.isLoading = true;
        this.http.get<any>(`${environment.apiUrl}/v1/sbc-routes`).subscribe({
            next: (response) => {
                this.routes = response.data || [];
                this.isLoading = false;
            },
            error: (error) => {
                console.error('Failed to load routes:', error);
                this.isLoading = false;
                this.showErrorMessage('Failed to load routes');
            },
        });
    }

    get filteredRoutes() {
        return this.routes.filter((d) => {
            return (
                (d.src_description || '').toLowerCase().includes(this.search.toLowerCase()) ||
                (d.dest_description || '').toLowerCase().includes(this.search.toLowerCase()) ||
                this.getSbcName(d.src_call_server_id).toLowerCase().includes(this.search.toLowerCase()) ||
                this.getSbcName(d.dest_call_server_id).toLowerCase().includes(this.search.toLowerCase()) ||
                (d.src_pattern || '').toLowerCase().includes(this.search.toLowerCase()) ||
                (d.dest_pattern || '').toLowerCase().includes(this.search.toLowerCase())
            );
        });
    }

    loadCallServers() {
        this.http.get<any>(`${environment.apiUrl}/v1/call-servers`).subscribe({
            next: (response) => { this.callServers = response.data || []; },
            error: (error) => { console.error('Failed to load call servers:', error); },
        });
    }

    loadSBCs() {
        this.http.get<any>(`${environment.apiUrl}/v1/call-servers?type=sbc`).subscribe({
            next: (response) => { this.sbcs = response.data || []; },
            error: (error) => { console.error('Failed to load SBC nodes:', error); },
        });
    }

    loadTrunks() {
        this.http.get<any>(`${environment.apiUrl}/v1/sbcs`).subscribe({
            next: (response) => { this.trunks = response.data || []; },
            error: (error) => { console.error('Failed to load connections:', error); },
        });
    }

    onNameSync(value: string) {
        if (!value) {
            this.formData.src_description = '';
            this.formData.dest_description = '';
            return;
        }
        this.formData.src_description = 'S-' + value;
        this.formData.dest_description = 'D-' + value;
    }

    openCreateModal() { this.modalMode = 'create'; this.resetForm(); this.showModal = true; }
    openEditModal(route: SBCRoute) { this.modalMode = 'edit'; this.formData = { ...route }; this.showModal = true; }
    copyRecord(route: SBCRoute) { this.modalMode = 'create'; this.formData = { ...route, id: undefined, src_pattern: route.src_pattern + '-new' }; this.showModal = true; }
    closeModal() { this.showModal = false; this.resetForm(); }
    resetForm() {
        this.masterName = '';
        this.formData = {
            src_call_server_id: null, src_description: '', src_pattern: '', src_cid_filter: null, src_priority: 0, src_is_active: true, src_from_sbc_id: null, src_destination_id: null,
            dest_call_server_id: null, dest_description: '', dest_pattern: '', dest_cid_filter: null, dest_priority: 0, dest_is_active: true, dest_from_sbc_id: null, dest_destination_id: null,
        };
    }

    handleSubmit() {
        if (this.modalMode === 'create') { this.createRoute(); }
        else if (this.modalMode === 'edit') { this.updateRoute(); }
    }

    createRoute() {
        const createData = { src_call_server_id: this.formData.src_call_server_id, src_description: this.formData.src_description, src_pattern: this.formData.src_pattern, src_cid_filter: this.formData.src_cid_filter, src_priority: this.formData.src_priority, src_is_active: this.formData.src_is_active, src_from_sbc_id: this.formData.src_from_sbc_id, src_destination_id: this.formData.src_destination_id, dest_call_server_id: this.formData.dest_call_server_id, dest_description: this.formData.dest_description, dest_pattern: this.formData.dest_pattern, dest_cid_filter: this.formData.dest_cid_filter, dest_priority: this.formData.dest_priority, dest_is_active: this.formData.dest_is_active, dest_from_sbc_id: this.formData.dest_from_sbc_id, dest_destination_id: this.formData.dest_destination_id };
        this.http.post<any>(`${environment.apiUrl}/v1/sbc-routes`, createData).subscribe({
            next: () => { this.showSuccessMessage('Route created successfully'); this.closeModal(); this.loadRoutes(); },
            error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to create route'); },
        });
    }

    updateRoute() {
        const updateData = { src_call_server_id: this.formData.src_call_server_id, src_description: this.formData.src_description, src_pattern: this.formData.src_pattern, src_cid_filter: this.formData.src_cid_filter, src_priority: this.formData.src_priority, src_is_active: this.formData.src_is_active, src_from_sbc_id: this.formData.src_from_sbc_id, src_destination_id: this.formData.src_destination_id, dest_call_server_id: this.formData.dest_call_server_id, dest_description: this.formData.dest_description, dest_pattern: this.formData.dest_pattern, dest_cid_filter: this.formData.dest_cid_filter, dest_priority: this.formData.dest_priority, dest_is_active: this.formData.dest_is_active, dest_from_sbc_id: this.formData.dest_from_sbc_id, dest_destination_id: this.formData.dest_destination_id };
        this.http.put<any>(`${environment.apiUrl}/v1/sbc-routes/${this.formData.id}`, updateData).subscribe({
            next: () => { this.showSuccessMessage('Route updated successfully'); this.closeModal(); this.loadRoutes(); },
            error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to update route'); },
        });
    }

    deleteRoute(id: number) {
        Swal.fire({ title: 'Are you sure?', text: 'You will not be able to recover this route!', icon: 'warning', showCancelButton: true, confirmButtonColor: '#3085d6', cancelButtonColor: '#d33', confirmButtonText: 'Yes, delete it!' }).then((result) => {
            if (result.isConfirmed) {
                this.http.delete<any>(`${environment.apiUrl}/v1/sbc-routes/${id}`).subscribe({
                    next: () => { this.showSuccessMessage('Route deleted successfully'); this.loadRoutes(); },
                    error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to delete route'); },
                });
            }
        });
    }

    getSbcName(id: number | null): string {
        if (!id) return '-';
        const sbc = this.sbcs.find(s => s.id === id);
        return sbc ? sbc.name : '-';
    }

    getTrunkName(id: number | null): string {
        if (!id) return '-';
        const trunk = this.trunks.find(t => t.id === id);
        return trunk ? trunk.name : '-';
    }

    showSuccessMessage(msg: string) { Swal.fire({ icon: 'success', title: 'Success', text: msg, timer: 2000, showConfirmButton: false }); }
    showErrorMessage(msg: string) { Swal.fire({ icon: 'error', title: 'Error', text: msg }); }
}
