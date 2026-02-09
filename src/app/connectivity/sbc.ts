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
import { IconEyeComponent } from '../shared/icon/icon-eye';
import Swal from 'sweetalert2';

interface SBCNode {
    id?: number;
    name: string;
    host: string;
    port: number;
    description: string | null;
    is_active: boolean;
    type: string;
}

@Component({
    templateUrl: './sbc.html',
    animations: [toggleAnimation],
    imports: [
        CommonModule,
        FormsModule,
        RouterModule,
        IconPlusComponent,
        IconPencilComponent,
        IconTrashLinesComponent,
        IconCircleCheckComponent,
        IconXCircleComponent,
        IconCopyComponent,
        IconEyeComponent,
    ],
})
export class SBCComponent implements OnInit {
    store: any;
    sbcs: SBCNode[] = [];
    isLoading = false;
    search = '';
    showModal = false;
    modalMode: 'create' | 'edit' | 'view' = 'create';

    // Report View
    showReportModal = false;
    reportData: SBCNode | null = null;
    reportGeneratedDate: Date = new Date();

    formData: SBCNode = {
        name: '',
        host: '',
        port: 5060,
        description: null,
        is_active: true,
        type: 'sbc'
    };

    private http = inject(HttpClient);

    constructor(public storeData: Store<any>, public router: Router) {
        this.initStore();
    }

    async initStore() { this.storeData.select((d) => d.index).subscribe((d) => { this.store = d; }); }

    ngOnInit() { this.loadSBCs(); }

    loadSBCs() {
        this.isLoading = true;
        this.http.get<any>(`${environment.apiUrl}/v1/call-servers?type=sbc`).subscribe({
            next: (response) => { this.sbcs = response.data || []; this.isLoading = false; },
            error: (error) => { console.error('Failed to load SBCs:', error); this.isLoading = false; this.showErrorMessage('Failed to load SBCs'); },
        });
    }

    get filteredSBCs() {
        return this.sbcs.filter((d) => {
            return (
                d.name.toLowerCase().includes(this.search.toLowerCase()) ||
                d.host.toLowerCase().includes(this.search.toLowerCase())
            );
        });
    }

    openCreateModal() { this.modalMode = 'create'; this.resetForm(); this.showModal = true; }
    openEditModal(sbc: SBCNode) { this.modalMode = 'edit'; this.formData = { ...sbc }; this.showModal = true; }
    copyRecord(sbc: SBCNode) { this.modalMode = 'create'; this.formData = { ...sbc, id: undefined, name: sbc.name + ' - Copy' }; this.showModal = true; }
    closeModal() { this.showModal = false; this.resetForm(); }

    // Report View Functions
    openReportView(sbc: SBCNode) {
        this.reportData = { ...sbc };
        this.reportGeneratedDate = new Date();
        this.showReportModal = true;
    }
    closeReportModal() { this.showReportModal = false; this.reportData = null; }
    printReport() { window.print(); }
    resetForm() {
        this.formData = {
            name: '',
            host: '',
            port: 5060,
            description: null,
            is_active: true,
            type: 'sbc'
        };
    }

    handleSubmit() {
        if (this.modalMode === 'create') { this.createSBC(); }
        else if (this.modalMode === 'edit') { this.updateSBC(); }
    }

    createSBC() {
        const createData = { ...this.formData };
        this.http.post<any>(`${environment.apiUrl}/v1/call-servers`, createData).subscribe({
            next: () => { this.showSuccessMessage('SBC Node created successfully'); this.closeModal(); this.loadSBCs(); },
            error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to create SBC Node'); },
        });
    }

    updateSBC() {
        const updateData = { ...this.formData };
        this.http.put<any>(`${environment.apiUrl}/v1/call-servers/${this.formData.id}`, updateData).subscribe({
            next: () => { this.showSuccessMessage('SBC Node updated successfully'); this.closeModal(); this.loadSBCs(); },
            error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to update SBC Node'); },
        });
    }

    deleteSBC(id: number) {
        Swal.fire({ title: 'Are you sure?', text: 'You will not be able to recover this SBC Node!', icon: 'warning', showCancelButton: true, confirmButtonColor: '#3085d6', cancelButtonColor: '#d33', confirmButtonText: 'Yes, delete it!' }).then((result) => {
            if (result.isConfirmed) {
                this.http.delete<any>(`${environment.apiUrl}/v1/call-servers/${id}`).subscribe({
                    next: () => { this.showSuccessMessage('SBC Node deleted successfully'); this.loadSBCs(); },
                    error: (error) => { this.showErrorMessage(error.error?.error || 'Failed to delete SBC Node'); },
                });
            }
        });
    }

    showSuccessMessage(msg: string) { Swal.fire({ icon: 'success', title: 'Success', text: msg, timer: 2000, showConfirmButton: false }); }
    showErrorMessage(msg: string) { Swal.fire({ icon: 'error', title: 'Error', text: msg }); }
}
