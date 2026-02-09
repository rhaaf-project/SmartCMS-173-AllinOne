import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../environments/environment';
import { Store } from '@ngrx/store';
import { toggleAnimation } from '../shared/animations';
import { IconPlusComponent } from '../shared/icon/icon-plus';
import { IconPencilComponent } from '../shared/icon/icon-pencil';
import { IconTrashLinesComponent } from '../shared/icon/icon-trash-lines';
import { IconCircleCheckComponent } from '../shared/icon/icon-circle-check';
import { IconCopyComponent } from '../shared/icon/icon-copy';
import Swal from 'sweetalert2';
import { NgScrollbarModule } from 'ngx-scrollbar';

@Component({
    templateUrl: './ivr-list.html',
    imports: [
        CommonModule,
        FormsModule,
        IconPlusComponent,
        IconPencilComponent,
        IconTrashLinesComponent,
        IconCircleCheckComponent,
        IconCopyComponent,
        NgScrollbarModule
    ],
    standalone: true,
    animations: [toggleAnimation],
})
export class IvrListComponent implements OnInit {
    store: any;
    isLoading = true;
    ivrs: any[] = [];
    callServers: any[] = [];
    announcements: any[] = [];
    recordings: any[] = [];
    search = '';

    showModal = false;
    modalMode: 'create' | 'edit' = 'create';

    // Form Data
    form: any = {
        id: null,
        name: '',
        description: '',
        call_server_id: null,
        announcement: null,
        direct_dial: 'Disabled',
        force_strict_dial_timeout: 'no',
        timeout_time: 10,
        alert_info: '',
        volume_override: 0,
        invalid_retries: 3,
        invalid_retry_recording: null,
        append_announcement_to_invalid: 1,
        return_on_invalid: 0,
        invalid_recording: null,
        invalid_destination: '',
        timeout_retries: 3,
        timeout_retry_recording: null,
        append_announcement_on_timeout: 1,
        return_on_timeout: 0,
        timeout_recording: null,
        timeout_destination: '',
        return_to_ivr_after_vm: 1,
        entries: [] // Array of { digits, destination, return_to_ivr }
    };

    private http = inject(HttpClient);

    constructor(public storeData: Store<any>) {
        this.initStore();
    }

    async initStore() {
        this.storeData.select((d) => d.index).subscribe((d) => {
            this.store = d;
        });
    }

    ngOnInit() {
        this.loadIvrs();
        this.loadDependencies();
    }

    loadIvrs() {
        this.isLoading = true;
        this.http.get<any>(`${environment.apiUrl}/v1/ivr`).subscribe({
            next: (res) => {
                this.ivrs = res.data || [];
                this.isLoading = false;
            },
            error: (err) => {
                console.error('Failed to load IVRs', err);
                this.isLoading = false;
            }
        });
    }

    loadDependencies() {
        this.http.get<any>(`${environment.apiUrl}/v1/call-servers`).subscribe(res => {
            this.callServers = res.data || [];
        });

        this.http.get<any>(`${environment.apiUrl}/v1/dropdowns?type=announcements`).subscribe(res => {
            this.announcements = res.data || [];
        });

        this.http.get<any>(`${environment.apiUrl}/v1/dropdowns?type=recordings`).subscribe(res => {
            this.recordings = res.data || [];
        });
    }

    openModal(mode: 'create' | 'edit', item: any = null) {
        this.modalMode = mode;
        this.showModal = true;

        if (mode === 'edit' && item) {
            this.form = JSON.parse(JSON.stringify(item));
            if (!this.form.entries) this.form.entries = [];
        } else {
            this.resetForm();
        }
    }

    resetForm() {
        this.form = {
            id: null,
            name: '',
            description: '',
            call_server_id: null,
            announcement: null,
            direct_dial: 'Disabled',
            timeout_time: 10,
            alert_info: '',
            volume_override: 0,
            invalid_retries: 3,
            invalid_retry_recording: null,
            append_announcement_to_invalid: 1,
            return_on_invalid: 0,
            invalid_recording: null,
            invalid_destination: '',
            entries: []
        };
    }

    closeModal() {
        this.showModal = false;
    }

    addEntry() {
        this.form.entries.push({
            digits: '',
            destination: '',
            return_to_ivr: false
        });
    }

    removeEntry(index: number) {
        this.form.entries.splice(index, 1);
    }

    saveIvr() {
        if (!this.form.name || !this.form.call_server_id) {
            this.showMessage('Please fill required fields (Name, Call Server)', 'error');
            return;
        }

        const url = `${environment.apiUrl}/v1/ivr`;
        const method = this.modalMode === 'create'
            ? this.http.post(url, this.form)
            : this.http.put(url, this.form);

        method.subscribe({
            next: () => {
                this.showMessage(`IVR ${this.modalMode === 'create' ? 'created' : 'updated'} successfully`);
                this.closeModal();
                this.loadIvrs();
            },
            error: (err) => {
                console.error('Failed to save IVR', err);
                this.showMessage('Failed to save IVR', 'error');
            }
        });
    }

    deleteIvr(id: number) {
        Swal.fire({
            title: 'Are you sure?',
            text: 'You will not be able to recover this IVR!',
            icon: 'warning',
            showCancelButton: true,
            confirmButtonText: 'Yes, delete it!',
            cancelButtonText: 'Cancel',
        }).then((result) => {
            if (result.isConfirmed) {
                this.http.delete(`${environment.apiUrl}/v1/ivr/${id}`).subscribe({
                    next: () => {
                        this.showMessage('IVR deleted successfully');
                        this.loadIvrs();
                    },
                    error: (err) => this.showMessage('Failed to delete IVR', 'error')
                });
            }
        });
    }

    showMessage(msg: string, type: 'success' | 'error' = 'success') {
        Swal.fire({
            icon: type,
            title: type === 'error' ? 'Error' : 'Success',
            text: msg,
            timer: 2000,
            showConfirmButton: false,
        });
    }
}
