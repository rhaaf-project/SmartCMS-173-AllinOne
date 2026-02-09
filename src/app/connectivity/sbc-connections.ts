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

interface SBCConnection {
    id?: number;
    // SBC Details
    call_server_id: number | null;
    call_server?: { id: number; name: string };
    name: string;
    outcid: string | null;
    maxchans: number;
    disabled: boolean;
    // SIP Server Settings
    sip_server: string;
    sip_server_port: number;
    transport: string;
    context: string;
    // Codec & DTMF
    codecs: string;
    dtmfmode: string;
    // Registration & Authentication
    registration: string;
    auth_username: string | null;
    secret: string | null;
    // Qualify Settings
    qualify: boolean;
    qualify_frequency: number;
}

interface SBCNode { id: number; name: string; }

@Component({
    templateUrl: './sbc-connections.html',
    animations: [toggleAnimation],
    imports: [CommonModule, FormsModule, RouterModule, IconPlusComponent, IconPencilComponent, IconTrashLinesComponent, IconCircleCheckComponent, IconXCircleComponent, IconCopyComponent],
})
export class SBCConnectionsComponent implements OnInit {
    store: any;
    connections: SBCConnection[] = [];
    sbcNodes: SBCNode[] = [];
    isLoading = false;
    search = '';
    showModal = false;
    modalMode: 'create' | 'edit' | 'view' = 'create';

    transportOptions = [{ value: 'udp', label: 'UDP' }, { value: 'tcp', label: 'TCP' }, { value: 'tls', label: 'TLS' }];
    dtmfModeOptions = [{ value: 'auto', label: 'Auto' }, { value: 'rfc2833', label: 'RFC2833' }, { value: 'inband', label: 'Inband' }, { value: 'info', label: 'INFO' }];
    registrationOptions = [{ value: 'none', label: 'None' }, { value: 'send', label: 'Send' }, { value: 'receive', label: 'Receive' }];

    formData: SBCConnection = {
        call_server_id: null, name: '', outcid: null, maxchans: 2, disabled: false,
        sip_server: '', sip_server_port: 5060, transport: 'udp', context: 'from-pstn',
        codecs: 'ulaw,alaw', dtmfmode: 'auto',
        registration: 'none', auth_username: null, secret: null,
        qualify: true, qualify_frequency: 60
    };

    private http = inject(HttpClient);

    constructor(public storeData: Store<any>, public router: Router) {
        this.initStore();
    }

    async initStore() { this.storeData.select((d) => d.index).subscribe((d) => { this.store = d; }); }

    ngOnInit() { this.loadConnections(); this.loadSbcNodes(); }

    loadConnections() {
        this.isLoading = true;
        this.http.get<any>(`${environment.apiUrl}/v1/sbcs`).subscribe({
            next: (response) => {
                this.connections = response.data || [];
                this.isLoading = false;
            },
            error: (error) => {
                console.error('Failed to load connections:', error);
                this.isLoading = false;
                this.showErrorMessage('Failed to load connections');
            },
        });
    }

    get filteredConnections() {
        return this.connections.filter((d) => {
            return (
                d.name.toLowerCase().includes(this.search.toLowerCase()) ||
                d.sip_server.toLowerCase().includes(this.search.toLowerCase()) ||
                (d.call_server?.name || '').toLowerCase().includes(this.search.toLowerCase())
            );
        });
    }

    loadSbcNodes() {
        this.http.get<any>(`${environment.apiUrl}/v1/call-servers?type=sbc`).subscribe({
            next: (response) => { this.sbcNodes = response.data || []; },
            error: (error) => { console.error('Failed to load SBC nodes:', error); },
        });
    }

    openCreateModal() { this.modalMode = 'create'; this.resetForm(); this.showModal = true; }
    openEditModal(conn: SBCConnection) { this.modalMode = 'edit'; this.formData = { ...conn }; this.showModal = true; }
    copyRecord(conn: SBCConnection) {
        this.modalMode = 'create';
        this.formData = { ...conn, id: undefined, name: conn.name + ' - New' };
        this.showModal = true;
    }
    closeModal() { this.showModal = false; this.resetForm(); }
    resetForm() {
        this.formData = {
            call_server_id: null, name: '', outcid: null, maxchans: 2, disabled: false,
            sip_server: '', sip_server_port: 5060, transport: 'udp', context: 'from-pstn',
            codecs: 'ulaw,alaw', dtmfmode: 'auto',
            registration: 'none', auth_username: null, secret: null,
            qualify: true, qualify_frequency: 60
        };
    }

    handleSubmit() {
        if (this.modalMode === 'create') { this.createConnection(); }
        else if (this.modalMode === 'edit') { this.updateConnection(); }
    }

    createConnection() {
        const createData = { call_server_id: this.formData.call_server_id, name: this.formData.name, outcid: this.formData.outcid, maxchans: this.formData.maxchans, disabled: this.formData.disabled, sip_server: this.formData.sip_server, sip_server_port: this.formData.sip_server_port, transport: this.formData.transport, context: this.formData.context, codecs: this.formData.codecs, dtmfmode: this.formData.dtmfmode, registration: this.formData.registration, auth_username: this.formData.auth_username, secret: this.formData.secret, qualify: this.formData.qualify, qualify_frequency: this.formData.qualify_frequency };
        this.http.post<any>(`${environment.apiUrl}/v1/sbcs`, createData).subscribe({
            next: () => { this.showSuccessMessage('Connection created successfully'); this.closeModal(); this.loadConnections(); },
            error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to create connection'); },
        });
    }

    updateConnection() {
        const updateData = { call_server_id: this.formData.call_server_id, name: this.formData.name, outcid: this.formData.outcid, maxchans: this.formData.maxchans, disabled: this.formData.disabled, sip_server: this.formData.sip_server, sip_server_port: this.formData.sip_server_port, transport: this.formData.transport, context: this.formData.context, codecs: this.formData.codecs, dtmfmode: this.formData.dtmfmode, registration: this.formData.registration, auth_username: this.formData.auth_username, secret: this.formData.secret, qualify: this.formData.qualify, qualify_frequency: this.formData.qualify_frequency };
        this.http.put<any>(`${environment.apiUrl}/v1/sbcs/${this.formData.id}`, updateData).subscribe({
            next: () => { this.showSuccessMessage('Connection updated successfully'); this.closeModal(); this.loadConnections(); },
            error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to update connection'); },
        });
    }

    deleteConnection(id: number) {
        Swal.fire({ title: 'Are you sure?', text: 'You will not be able to recover this connection!', icon: 'warning', showCancelButton: true, confirmButtonColor: '#3085d6', cancelButtonColor: '#d33', confirmButtonText: 'Yes, delete it!' }).then((result) => {
            if (result.isConfirmed) {
                this.http.delete<any>(`${environment.apiUrl}/v1/sbcs/${id}`).subscribe({
                    next: () => { this.showSuccessMessage('Connection deleted successfully'); this.loadConnections(); },
                    error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to delete connection'); },
                });
            }
        });
    }

    showSuccessMessage(msg: string) { Swal.fire({ icon: 'success', title: 'Success', text: msg, timer: 2000, showConfirmButton: false }); }
    showErrorMessage(msg: string) { Swal.fire({ icon: 'error', title: 'Error', text: msg }); }
}
