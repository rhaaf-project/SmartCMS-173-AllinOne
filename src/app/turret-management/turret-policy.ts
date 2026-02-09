import { Component, inject, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { RouterModule } from '@angular/router';
import { toggleAnimation } from '../shared/animations';
import { environment } from '../../environments/environment';
import { IconPencilComponent } from '../shared/icon/icon-pencil';
import { IconTrashLinesComponent } from '../shared/icon/icon-trash-lines';
import { IconCopyComponent } from '../shared/icon/icon-copy';
import Swal from 'sweetalert2';

interface TurretPolicy {
    id?: number;
    name: string;
    max_channels: number;
    allow_recording: boolean;
    allow_intercom: boolean;
    allow_group_talk: boolean;
    allow_external: boolean;
    description?: string;
    is_active: boolean;
}

@Component({
    selector: 'app-turret-policy',
    standalone: true,
    templateUrl: './turret-policy.html',
    animations: [toggleAnimation],
    imports: [
        CommonModule,
        FormsModule,
        RouterModule,
        IconPencilComponent,
        IconTrashLinesComponent,
        IconCopyComponent,
    ],
})
export class TurretPolicyComponent implements OnInit {
    items: TurretPolicy[] = [];
    isLoading = false;
    showModal = false;
    modalMode: 'create' | 'edit' = 'create';
    formData: TurretPolicy = {
        name: '',
        max_channels: 4,
        allow_recording: true,
        allow_intercom: true,
        allow_group_talk: true,
        allow_external: true,
        description: '',
        is_active: true
    };
    search = '';

    private http = inject(HttpClient);

    ngOnInit() {
        this.loadItems();
    }

    get filteredItems(): TurretPolicy[] {
        if (!this.search) return this.items;
        const s = this.search.toLowerCase();
        return this.items.filter(item =>
            item.name.toLowerCase().includes(s)
        );
    }

    loadItems() {
        this.isLoading = true;
        this.http.get<any>(`${environment.apiUrl}/v1/turret-policies`).subscribe({
            next: (res) => {
                this.items = res.data || [];
                this.isLoading = false;
            },
            error: () => {
                this.isLoading = false;
            }
        });
    }

    openCreateModal() {
        this.modalMode = 'create';
        this.formData = {
            name: '',
            max_channels: 4,
            allow_recording: true,
            allow_intercom: true,
            allow_group_talk: true,
            allow_external: true,
            description: '',
            is_active: true
        };
        this.showModal = true;
    }

    openEditModal(item: TurretPolicy) {
        this.modalMode = 'edit';
        this.formData = { ...item };
        this.showModal = true;
    }

    closeModal() {
        this.showModal = false;
    }

    saveRecord() {
        if (!this.formData.name) {
            Swal.fire('Error', 'Policy name is required', 'error');
            return;
        }

        const url = this.modalMode === 'create'
            ? `${environment.apiUrl}/v1/turret-policies`
            : `${environment.apiUrl}/v1/turret-policies/${this.formData.id}`;

        const method = this.modalMode === 'create' ? 'post' : 'put';

        this.http.request(method, url, { body: this.formData }).subscribe({
            next: () => {
                Swal.fire('Success', 'Policy saved successfully', 'success');
                this.closeModal();
                this.loadItems();
            },
            error: (err) => {
                Swal.fire('Error', err.error?.error || 'Failed to save policy', 'error');
            }
        });
    }

    copyRecord(item: TurretPolicy) {
        Swal.fire({
            title: 'Duplicate Policy?',
            text: `Create a copy of "${item.name}"?`,
            icon: 'question',
            showCancelButton: true,
            confirmButtonText: 'Yes, duplicate!'
        }).then((result) => {
            if (result.isConfirmed) {
                const copy: Partial<TurretPolicy> = {
                    name: `${item.name} (Copy)`,
                    max_channels: item.max_channels,
                    allow_recording: item.allow_recording,
                    allow_intercom: item.allow_intercom,
                    allow_group_talk: item.allow_group_talk,
                    allow_external: item.allow_external,
                    description: item.description,
                    is_active: item.is_active
                };

                this.http.post<any>(`${environment.apiUrl}/v1/turret-policies`, copy).subscribe({
                    next: () => {
                        this.loadItems();
                        Swal.fire('Success', 'Policy duplicated', 'success');
                    },
                    error: () => {
                        Swal.fire('Error', 'Failed to duplicate', 'error');
                    }
                });
            }
        });
    }

    deleteRecord(item: TurretPolicy) {
        Swal.fire({
            title: 'Delete Policy?',
            text: `Delete "${item.name}"?`,
            icon: 'warning',
            showCancelButton: true,
            confirmButtonText: 'Yes, delete!'
        }).then((result) => {
            if (result.isConfirmed) {
                this.http.delete<any>(`${environment.apiUrl}/v1/turret-policies/${item.id}`).subscribe({
                    next: () => {
                        this.loadItems();
                        Swal.fire('Deleted!', 'Policy deleted.', 'success');
                    },
                    error: () => {
                        Swal.fire('Error', 'Failed to delete', 'error');
                    }
                });
            }
        });
    }
}
