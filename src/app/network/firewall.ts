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
import { IconCircleCheckComponent } from '../shared/icon/icon-circle-check';
import { IconCopyComponent } from '../shared/icon/icon-copy';

interface FirewallRule {
    id?: number;
    name: string;
    protocol: 'TCP' | 'UDP' | 'ICMP' | 'ALL';
    port: string;
    source: string;
    action: 'ACCEPT' | 'DROP' | 'REJECT';
    priority: number;
    device_type: 'call_server' | 'sbc' | 'recording' | null;
    device_id: number | null;
    is_active: boolean;
}

interface Device {
    id: number;
    name: string;
    type?: string;
}

@Component({
    templateUrl: './firewall.html',
    imports: [
        CommonModule,
        FormsModule,
        IconPencilComponent,
        IconTrashLinesComponent,
        IconPlusComponent,
        IconCircleCheckComponent,
        IconCopyComponent,
    ],
    animations: [toggleAnimation],
})
export class FirewallComponent implements OnInit {
    search = '';
    showModal = false;
    modalMode: 'create' | 'edit' = 'create';
    isLoading = false;

    rules: FirewallRule[] = [];

    formData: FirewallRule = {
        name: '',
        protocol: 'UDP',
        port: '',
        source: 'Any',
        action: 'ACCEPT',
        priority: 100,
        device_type: null,
        device_id: null,
        is_active: true,
    };

    protocols = ['TCP', 'UDP', 'ICMP', 'ALL'];
    actions = ['ACCEPT', 'DROP', 'REJECT'];
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
        this.loadRules();
        this.loadDevices();
    }

    loadRules() {
        this.isLoading = true;
        this.http.get<any>(`${environment.apiUrl}/v1/firewall-rules`).subscribe({
            next: (response) => {
                this.rules = response.data || [];
                this.isLoading = false;
            },
            error: (error) => {
                console.error('Failed to load rules:', error);
                this.isLoading = false;
            }
        });
    }

    loadDevices() {
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

    get filteredRules() {
        let filtered = this.rules;
        if (this.search) {
            const s = this.search.toLowerCase();
            filtered = this.rules.filter(r =>
                r.name.toLowerCase().includes(s) ||
                r.protocol.toLowerCase().includes(s) ||
                r.port.toLowerCase().includes(s) ||
                r.source.toLowerCase().includes(s)
            );
        }
        return filtered.sort((a, b) => a.priority - b.priority);
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

    getDeviceName(rule: FirewallRule): string {
        if (!rule.device_type || !rule.device_id) return '-';
        let devices: Device[] = [];
        switch (rule.device_type) {
            case 'call_server': devices = this.callServers; break;
            case 'sbc': devices = this.sbcs; break;
            case 'recording': devices = this.recordingServers; break;
        }
        const device = devices.find(d => d.id === rule.device_id);
        return device ? device.name : `ID: ${rule.device_id}`;
    }

    getDeviceTypeLabel(type: string | null): string {
        const found = this.deviceTypes.find(t => t.value === type);
        return found ? found.label : '-';
    }

    openCreateModal() {
        this.modalMode = 'create';
        this.formData = { name: '', protocol: 'UDP', port: '', source: 'Any', action: 'ACCEPT', priority: 100, device_type: null, device_id: null, is_active: true };
        this.showModal = true;
    }

    openEditModal(rule: FirewallRule) {
        this.modalMode = 'edit';
        this.formData = { ...rule };
        this.showModal = true;
    }

    closeModal() {
        this.showModal = false;
    }

    handleSubmit() {
        if (!this.formData.name || !this.formData.port) {
            this.showMessage('Name and Port are required', 'error');
            return;
        }
        if (!this.formData.device_type || !this.formData.device_id) {
            this.showMessage('Please select a device', 'error');
            return;
        }

        const payload = {
            name: this.formData.name,
            protocol: this.formData.protocol,
            port: this.formData.port,
            source: this.formData.source,
            action: this.formData.action,
            priority: this.formData.priority,
            device_type: this.formData.device_type,
            device_id: this.formData.device_id,
            is_active: this.formData.is_active,
        };

        if (this.modalMode === 'create') {
            this.http.post<any>(`${environment.apiUrl}/v1/firewall-rules`, payload).subscribe({
                next: () => { this.showMessage('Rule created successfully'); this.closeModal(); this.loadRules(); },
                error: (error) => this.showMessage(error.error?.error || 'Failed to create rule', 'error')
            });
        } else {
            this.http.put<any>(`${environment.apiUrl}/v1/firewall-rules/${this.formData.id}`, payload).subscribe({
                next: () => { this.showMessage('Rule updated successfully'); this.closeModal(); this.loadRules(); },
                error: (error) => this.showMessage(error.error?.error || 'Failed to update rule', 'error')
            });
        }
    }

    deleteRule(id: number) {
        Swal.fire({
            title: 'Are you sure?',
            text: 'This firewall rule will be deleted!',
            icon: 'warning',
            showCancelButton: true,
            confirmButtonText: 'Yes, delete it!',
        }).then((result) => {
            if (result.isConfirmed) {
                this.http.delete<any>(`${environment.apiUrl}/v1/firewall-rules/${id}`).subscribe({
                    next: () => { this.showMessage('Rule deleted successfully'); this.loadRules(); },
                    error: (error) => this.showMessage(error.error?.error || 'Failed to delete rule', 'error')
                });
            }
        });
    }

    getActionClass(action: string): string {
        switch (action) {
            case 'ACCEPT': return 'badge bg-success';
            case 'DROP': return 'badge bg-danger';
            case 'REJECT': return 'badge bg-warning';
            default: return 'badge bg-dark';
        }
    }

    copyRecord(rule: FirewallRule) {
        this.modalMode = 'create';
        this.formData = { ...rule, id: undefined, name: rule.name + ' (copy)' };
        this.showModal = true;
    }

    showMessage(msg: string, type: 'success' | 'error' = 'success') {
        Swal.fire({ icon: type, title: type === 'error' ? 'Error' : 'Success', text: msg, timer: 2000, showConfirmButton: false });
    }
}
