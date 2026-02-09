import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { toggleAnimation } from '../shared/animations';
import { environment } from '../../environments/environment';
import Swal from 'sweetalert2';

// Icons
import { IconPencilComponent } from '../shared/icon/icon-pencil';
import { IconTrashLinesComponent } from '../shared/icon/icon-trash-lines';
import { IconPlusComponent } from '../shared/icon/icon-plus';
import { IconCopyComponent } from '../shared/icon/icon-copy';

interface StaticRoute {
    id?: number;
    destination: string;
    gateway: string;
    interface_name: string;
    metric: number;
    device_type: 'call_server' | 'sbc' | 'recording' | null;
    device_id: number | null;
    is_active: boolean;
    device?: { id: number; name: string };
}

interface Device {
    id: number;
    name: string;
    type?: string;
}

@Component({
    templateUrl: './static-route.html',
    imports: [
        CommonModule,
        FormsModule,
        IconPencilComponent,
        IconTrashLinesComponent,
        IconPlusComponent,
        IconCopyComponent,
    ],
    animations: [toggleAnimation],
})
export class StaticRouteComponent implements OnInit {
    search = '';
    showModal = false;
    modalMode: 'create' | 'edit' = 'create';
    isLoading = false;

    routes: StaticRoute[] = [];

    formData: StaticRoute = {
        destination: '',
        gateway: '',
        interface_name: 'eth0',
        metric: 100,
        device_type: null,
        device_id: null,
        is_active: true,
    };

    interfaces = ['eth0', 'eth1', 'eth2', 'bond0', 'lo'];
    deviceTypes = [
        { value: 'call_server', label: 'Call Server' },
        { value: 'sbc', label: 'SBC' },
        { value: 'recording', label: 'Recording Server' },
    ];

    // Device lists
    callServers: Device[] = [];
    sbcs: Device[] = [];
    recordingServers: Device[] = [];

    private http = inject(HttpClient);

    constructor() { }

    ngOnInit(): void {
        this.loadRoutes();
        this.loadDevices();
    }

    loadRoutes() {
        this.isLoading = true;
        this.http.get<any>(`${environment.apiUrl}/v1/static-routes`).subscribe({
            next: (response) => {
                this.routes = response.data || [];
                this.isLoading = false;
            },
            error: (error) => {
                console.error('Failed to load routes:', error);
                this.isLoading = false;
            }
        });
    }

    loadDevices() {
        // Load Call Servers
        this.http.get<any>(`${environment.apiUrl}/v1/call-servers`).subscribe({
            next: (response) => {
                const all = response.data || [];
                this.callServers = all.filter((d: any) => d.type !== 'sbc' && d.type !== 'recording');
                this.sbcs = all.filter((d: any) => d.type === 'sbc');
                this.recordingServers = all.filter((d: any) => d.type === 'recording');
            },
            error: (error) => console.error('Failed to load devices:', error)
        });
    }

    get filteredRoutes() {
        if (!this.search) return this.routes;
        const s = this.search.toLowerCase();
        return this.routes.filter(r =>
            r.destination.toLowerCase().includes(s) ||
            r.gateway.toLowerCase().includes(s) ||
            r.interface_name.toLowerCase().includes(s)
        );
    }

    get availableDevices(): Device[] {
        switch (this.formData.device_type) {
            case 'call_server': return this.callServers;
            case 'sbc': return this.sbcs;
            case 'recording': return this.recordingServers;
            default: return [];
        }
    }

    onDeviceTypeChange() {
        this.formData.device_id = null;
    }

    getDeviceName(route: StaticRoute): string {
        if (!route.device_type || !route.device_id) return '-';
        let devices: Device[] = [];
        switch (route.device_type) {
            case 'call_server': devices = this.callServers; break;
            case 'sbc': devices = this.sbcs; break;
            case 'recording': devices = this.recordingServers; break;
        }
        const device = devices.find(d => d.id === route.device_id);
        return device ? device.name : `ID: ${route.device_id}`;
    }

    getDeviceTypeLabel(type: string | null): string {
        const found = this.deviceTypes.find(t => t.value === type);
        return found ? found.label : '-';
    }

    openCreateModal() {
        this.modalMode = 'create';
        this.formData = { destination: '', gateway: '', interface_name: 'eth0', metric: 100, device_type: null, device_id: null, is_active: true };
        this.showModal = true;
    }

    openEditModal(route: StaticRoute) {
        this.modalMode = 'edit';
        this.formData = { ...route };
        this.showModal = true;
    }

    closeModal() {
        this.showModal = false;
    }

    handleSubmit() {
        if (!this.formData.destination || !this.formData.gateway) {
            this.showMessage('Destination and Gateway are required', 'error');
            return;
        }
        if (!this.formData.device_type || !this.formData.device_id) {
            this.showMessage('Please select a device', 'error');
            return;
        }

        const payload = {
            destination: this.formData.destination,
            gateway: this.formData.gateway,
            interface_name: this.formData.interface_name,
            metric: this.formData.metric,
            device_type: this.formData.device_type,
            device_id: this.formData.device_id,
            is_active: this.formData.is_active,
        };

        if (this.modalMode === 'create') {
            this.http.post<any>(`${environment.apiUrl}/v1/static-routes`, payload).subscribe({
                next: () => { this.showMessage('Route created successfully'); this.closeModal(); this.loadRoutes(); },
                error: (error) => this.showMessage(error.error?.error || 'Failed to create route', 'error')
            });
        } else {
            this.http.put<any>(`${environment.apiUrl}/v1/static-routes/${this.formData.id}`, payload).subscribe({
                next: () => { this.showMessage('Route updated successfully'); this.closeModal(); this.loadRoutes(); },
                error: (error) => this.showMessage(error.error?.error || 'Failed to update route', 'error')
            });
        }
    }

    deleteRoute(id: number) {
        Swal.fire({
            title: 'Are you sure?',
            text: 'This route will be deleted!',
            icon: 'warning',
            showCancelButton: true,
            confirmButtonText: 'Yes, delete it!',
        }).then((result) => {
            if (result.isConfirmed) {
                this.http.delete<any>(`${environment.apiUrl}/v1/static-routes/${id}`).subscribe({
                    next: () => { this.showMessage('Route deleted successfully'); this.loadRoutes(); },
                    error: (error) => this.showMessage(error.error?.error || 'Failed to delete route', 'error')
                });
            }
        });
    }

    copyRecord(route: StaticRoute) {
        this.modalMode = 'create';
        this.formData = { ...route, id: undefined, destination: route.destination + ' (copy)' };
        this.showModal = true;
    }

    showMessage(msg: string, type: 'success' | 'error' = 'success') {
        Swal.fire({ icon: type, title: type === 'error' ? 'Error' : 'Success', text: msg, timer: 2000, showConfirmButton: false });
    }
}
