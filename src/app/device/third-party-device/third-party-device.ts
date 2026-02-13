import { Component, inject, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { Router, RouterModule } from '@angular/router';
import { Store } from '@ngrx/store';
import { toggleAnimation } from '../../shared/animations';
import { environment } from '../../../environments/environment';
import { IconPlusComponent } from '../../shared/icon/icon-plus';
import { IconPencilComponent } from '../../shared/icon/icon-pencil';
import { IconTrashLinesComponent } from '../../shared/icon/icon-trash-lines';
import { IconCircleCheckComponent } from '../../shared/icon/icon-circle-check';
import { IconCopyComponent } from '../../shared/icon/icon-copy';
import Swal from 'sweetalert2';

interface Device3rdParty {
    id?: number;
    name: string;
    device_type: string;
    manufacturer: string | null;
    ip_address: string | null;
    is_active: boolean;
}

@Component({
    templateUrl: './third-party-device.html',
    animations: [toggleAnimation],
    imports: [CommonModule, FormsModule, RouterModule, IconPlusComponent, IconPencilComponent, IconTrashLinesComponent, IconCircleCheckComponent, IconCopyComponent],
})
export class ThirdPartyDeviceComponent implements OnInit {
    store: any;
    devices: Device3rdParty[] = [];
    isLoading = false;
    search = '';
    showModal = false;
    modalMode: 'create' | 'edit' | 'view' = 'create';

    formData: Device3rdParty = { name: '', device_type: 'ip_phone', manufacturer: null, ip_address: null, is_active: true };

    private http = inject(HttpClient);

    constructor(public storeData: Store<any>, public router: Router) {
        this.initStore();
    }

    async initStore() { this.storeData.select((d) => d.index).subscribe((d) => { this.store = d; }); }

    ngOnInit() { this.loadDevices(); }

    loadDevices() {
        this.isLoading = true;
        this.http.get<any>(`${environment.apiUrl}/v1/device-3rd-parties`).subscribe({
            next: (response) => { this.devices = response.data || []; this.isLoading = false; },
            error: (error) => { console.error('Failed to load devices:', error); this.isLoading = false; this.showErrorMessage('Failed to load devices'); },
        });
    }

    openCreateModal() { this.modalMode = 'create'; this.resetForm(); this.showModal = true; }
    openEditModal(device: Device3rdParty) { this.modalMode = 'edit'; this.formData = { ...device }; this.showModal = true; }
    copyRecord(device: Device3rdParty) { this.modalMode = 'create'; this.formData = { ...device, id: undefined, name: device.name + ' - New' }; this.showModal = true; }
    closeModal() { this.showModal = false; this.resetForm(); }
    resetForm() { this.formData = { name: '', device_type: 'ip_phone', manufacturer: null, ip_address: null, is_active: true }; }

    handleSubmit() {
        if (this.modalMode === 'create') { this.createDevice(); }
        else if (this.modalMode === 'edit') { this.updateDevice(); }
    }

    createDevice() {
        const createData = { name: this.formData.name, device_type: this.formData.device_type, manufacturer: this.formData.manufacturer, ip_address: this.formData.ip_address, is_active: this.formData.is_active };
        this.http.post<any>(`${environment.apiUrl}/v1/device-3rd-parties`, createData).subscribe({
            next: () => { this.showSuccessMessage('Device created successfully'); this.closeModal(); this.loadDevices(); },
            error: (error) => { console.error('Failed to create device:', error); this.showErrorMessage(error.error?.error || 'Failed to create device'); },
        });
    }

    updateDevice() {
        const updateData = { name: this.formData.name, device_type: this.formData.device_type, manufacturer: this.formData.manufacturer, ip_address: this.formData.ip_address, is_active: this.formData.is_active };
        this.http.put<any>(`${environment.apiUrl}/v1/device-3rd-parties/${this.formData.id}`, updateData).subscribe({
            next: () => { this.showSuccessMessage('Device updated successfully'); this.closeModal(); this.loadDevices(); },
            error: (error) => { console.error('Failed to update device:', error); this.showErrorMessage(error.error?.error || 'Failed to update device'); },
        });
    }

    deleteDevice(id: number) {
        Swal.fire({ title: 'Are you sure?', text: 'You will not be able to recover this device!', icon: 'warning', showCancelButton: true, confirmButtonColor: '#3085d6', cancelButtonColor: '#d33', confirmButtonText: 'Yes, delete it!' }).then((result) => {
            if (result.isConfirmed) {
                this.http.delete<any>(`${environment.apiUrl}/v1/device-3rd-parties/${id}`).subscribe({
                    next: () => { this.showSuccessMessage('Device deleted successfully'); this.loadDevices(); },
                    error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to delete device'); },
                });
            }
        });
    }

    showSuccessMessage(msg: string) { Swal.fire({ icon: 'success', title: 'Success', text: msg, timer: 2000, showConfirmButton: false }); }
    showErrorMessage(msg: string) { Swal.fire({ icon: 'error', title: 'Error', text: msg }); }
}
