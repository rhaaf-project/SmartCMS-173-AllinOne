import { Component, inject, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { Router, RouterModule } from '@angular/router';
import { toggleAnimation } from '../shared/animations';
import { environment } from '../../environments/environment';
import { IconPencilComponent } from '../shared/icon/icon-pencil';
import { IconTrashLinesComponent } from '../shared/icon/icon-trash-lines';
import { IconCopyComponent } from '../shared/icon/icon-copy';
import Swal from 'sweetalert2';

interface TurretTemplate {
    id?: number;
    name: string;
    description?: string;
    layout_type: 'LTR' | 'RTL' | 'Standard';
    layout_json: string;
    created_at?: string;
}

@Component({
    selector: 'app-turret-template',
    standalone: true,
    templateUrl: './turret-template.html',
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
export class TurretTemplateComponent implements OnInit {
    items: TurretTemplate[] = [];
    isLoading = false;
    showModal = false;
    modalMode: 'create' | 'edit' = 'create';
    formData: TurretTemplate = { name: '', description: '', layout_type: 'LTR', layout_json: '[]' };
    search = '';

    private http = inject(HttpClient);

    ngOnInit() {
        this.loadItems();
    }

    get filteredItems(): TurretTemplate[] {
        if (!this.search) return this.items;
        const s = this.search.toLowerCase();
        return this.items.filter(item =>
            item.name.toLowerCase().includes(s)
        );
    }

    loadItems() {
        this.isLoading = true;
        this.http.get<any>(`${environment.apiUrl}/v1/turret-templates`).subscribe({
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
        // Default layout JSON (empty structure)
        const defaultLayout = Array(24).fill(null);
        this.formData = {
            name: '',
            description: '',
            layout_type: 'LTR',
            layout_json: JSON.stringify(defaultLayout, null, 2)
        };
        this.showModal = true;
    }

    openEditModal(item: TurretTemplate) {
        this.modalMode = 'edit';
        this.formData = { ...item };
        // Pretty print JSON
        try {
            const parsed = JSON.parse(this.formData.layout_json);
            this.formData.layout_json = JSON.stringify(parsed, null, 2);
        } catch (e) {
            // keep as is
        }
        this.showModal = true;
    }

    closeModal() {
        this.showModal = false;
    }

    saveRecord() {
        if (!this.formData.name) {
            Swal.fire('Error', 'Name is required', 'error');
            return;
        }

        // Validate JSON
        try {
            JSON.parse(this.formData.layout_json);
        } catch (e) {
            Swal.fire('Error', 'Invalid JSON format in Layout', 'error');
            return;
        }

        const url = this.modalMode === 'create'
            ? `${environment.apiUrl}/v1/turret-templates`
            : `${environment.apiUrl}/v1/turret-templates/${this.formData.id}`;

        const method = this.modalMode === 'create' ? 'post' : 'put';

        this.http.request(method, url, { body: this.formData }).subscribe({
            next: () => {
                Swal.fire('Success', 'Template saved successfully', 'success');
                this.closeModal();
                this.loadItems();
            },
            error: (err) => {
                Swal.fire('Error', err.error?.error || 'Failed to save template', 'error');
            }
        });
    }

    copyRecord(item: TurretTemplate) {
        Swal.fire({
            title: 'Duplicate Template?',
            text: `Create a copy of "${item.name}"?`,
            icon: 'question',
            showCancelButton: true,
            confirmButtonText: 'Yes, duplicate it!'
        }).then((result) => {
            if (result.isConfirmed) {
                const copy: TurretTemplate = {
                    name: `${item.name} (Copy)`,
                    description: item.description,
                    layout_type: item.layout_type,
                    layout_json: item.layout_json
                };

                this.http.post<any>(`${environment.apiUrl}/v1/turret-templates`, copy).subscribe({
                    next: () => {
                        this.loadItems();
                        Swal.fire('Success', 'Template duplicated successfully', 'success');
                    },
                    error: (err) => {
                        Swal.fire('Error', 'Failed to duplicate template', 'error');
                    }
                });
            }
        });
    }

    deleteRecord(item: TurretTemplate) {
        Swal.fire({
            title: 'Delete Template?',
            text: `Are you sure you want to delete "${item.name}"?`,
            icon: 'warning',
            showCancelButton: true,
            confirmButtonText: 'Yes, delete it!'
        }).then((result) => {
            if (result.isConfirmed) {
                this.http.delete<any>(`${environment.apiUrl}/v1/turret-templates/${item.id}`).subscribe({
                    next: () => {
                        this.loadItems();
                        Swal.fire('Deleted!', 'Template deleted.', 'success');
                    },
                    error: () => {
                        Swal.fire('Error', 'Failed to delete template', 'error');
                    }
                });
            }
        });
    }
}
