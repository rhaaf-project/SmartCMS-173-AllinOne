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

interface DialPattern {
    id?: number;
    outbound_routing_id?: number;
    prepend: string | null;
    prefix: string | null;
    match_pattern: string | null;
    caller_id: string | null;
}

interface OutboundRouting {
    id?: number;
    call_server_id: number | null;
    call_server?: { id: number; name: string };
    name: string;
    dial_pattern: string | null;
    trunk_id: number | null;
    priority: number;
    description: string | null;
    is_active: boolean;
    dial_patterns: DialPattern[];
}

interface CallServer { id: number; name: string; }
interface Trunk { id: number; name: string; }

@Component({
    templateUrl: './outbound-routing.html',
    animations: [toggleAnimation],
    imports: [CommonModule, FormsModule, RouterModule, IconPlusComponent, IconPencilComponent, IconTrashLinesComponent, IconCircleCheckComponent, IconCopyComponent],
})
export class OutboundRoutingComponent implements OnInit {
    store: any;
    routes: OutboundRouting[] = [];
    callServers: CallServer[] = [];
    trunks: Trunk[] = [];
    isLoading = false;
    search = '';
    showModal = false;
    modalMode: 'create' | 'edit' | 'view' = 'create';

    formData: OutboundRouting = { call_server_id: null, name: '', dial_pattern: null, trunk_id: null, priority: 0, description: null, is_active: true, dial_patterns: [] };

    private http = inject(HttpClient);

    constructor(public storeData: Store<any>, public router: Router) {
        this.initStore();
    }

    async initStore() { this.storeData.select((d) => d.index).subscribe((d) => { this.store = d; }); }

    ngOnInit() { this.loadRoutes(); this.loadCallServers(); this.loadTrunks(); }

    loadRoutes() {
        this.isLoading = true;
        this.http.get<any>(`${environment.apiUrl}/v1/outbound-routings`).subscribe({
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

    loadTrunks() {
        this.http.get<any>(`${environment.apiUrl}/v1/trunks`).subscribe({
            next: (response) => { this.trunks = response.data || []; },
            error: (error) => { console.error('Failed to load trunks:', error); },
        });
    }

    openCreateModal() { this.modalMode = 'create'; this.resetForm(); this.showModal = true; }
    openEditModal(route: OutboundRouting) {
        this.modalMode = 'edit';
        // Load full route data with dial_patterns
        this.http.get<any>(`${environment.apiUrl}/v1/outbound-routings/${route.id}`).subscribe({
            next: (response) => {
                this.formData = { ...response.data, dial_patterns: response.data.dial_patterns || [] };
                this.showModal = true;
            },
            error: () => {
                this.formData = { ...route, dial_patterns: route.dial_patterns || [] };
                this.showModal = true;
            }
        });
    }
    copyRecord(route: OutboundRouting) {
        this.modalMode = 'create';
        this.formData = {
            ...route,
            id: undefined,
            name: route.name + ' - New',
            dial_patterns: (route.dial_patterns || []).map(p => ({ ...p, id: undefined, outbound_routing_id: undefined }))
        };
        this.showModal = true;
    }
    closeModal() { this.showModal = false; this.resetForm(); }
    resetForm() { this.formData = { call_server_id: null, name: '', dial_pattern: null, trunk_id: null, priority: 0, description: null, is_active: true, dial_patterns: [] }; }

    // Dial Pattern Management
    addDialPattern() {
        this.formData.dial_patterns.push({ prepend: null, prefix: null, match_pattern: null, caller_id: null });
    }
    removeDialPattern(index: number) {
        this.formData.dial_patterns.splice(index, 1);
    }
    trackByIndex(index: number): number {
        return index;
    }

    handleSubmit() {
        if (this.modalMode === 'create') { this.createRoute(); }
        else if (this.modalMode === 'edit') { this.updateRoute(); }
    }

    createRoute() {
        const createData = {
            call_server_id: this.formData.call_server_id,
            name: this.formData.name,
            dial_pattern: this.formData.dial_pattern,
            trunk_id: this.formData.trunk_id,
            priority: this.formData.priority,
            description: this.formData.description,
            is_active: this.formData.is_active,
            dial_patterns: this.formData.dial_patterns
        };
        this.http.post<any>(`${environment.apiUrl}/v1/outbound-routings`, createData).subscribe({
            next: () => { this.showSuccessMessage('Route created successfully'); this.closeModal(); this.loadRoutes(); },
            error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to create route'); },
        });
    }

    updateRoute() {
        const updateData = {
            call_server_id: this.formData.call_server_id,
            name: this.formData.name,
            dial_pattern: this.formData.dial_pattern,
            trunk_id: this.formData.trunk_id,
            priority: this.formData.priority,
            description: this.formData.description,
            is_active: this.formData.is_active,
            dial_patterns: this.formData.dial_patterns
        };
        this.http.put<any>(`${environment.apiUrl}/v1/outbound-routings/${this.formData.id}`, updateData).subscribe({
            next: () => { this.showSuccessMessage('Route updated successfully'); this.closeModal(); this.loadRoutes(); },
            error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to update route'); },
        });
    }

    deleteRoute(id: number) {
        Swal.fire({ title: 'Are you sure?', text: 'You will not be able to recover this route!', icon: 'warning', showCancelButton: true, confirmButtonColor: '#3085d6', cancelButtonColor: '#d33', confirmButtonText: 'Yes, delete it!' }).then((result) => {
            if (result.isConfirmed) {
                this.http.delete<any>(`${environment.apiUrl}/v1/outbound-routings/${id}`).subscribe({
                    next: () => { this.showSuccessMessage('Route deleted successfully'); this.loadRoutes(); },
                    error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to delete route'); },
                });
            }
        });
    }

    showSuccessMessage(msg: string) { Swal.fire({ icon: 'success', title: 'Success', text: msg, timer: 2000, showConfirmButton: false }); }
    showErrorMessage(msg: string) { Swal.fire({ icon: 'error', title: 'Error', text: msg }); }
}
