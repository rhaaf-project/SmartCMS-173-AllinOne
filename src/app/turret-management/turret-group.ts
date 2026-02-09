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

interface TurretGroup {
    id?: number;
    name: string;
    description?: string;
    is_active: boolean;
    members?: string[]; // Array of extension numbers
}

interface Extension {
    id: number;
    name: string;
    extension: string;
}

@Component({
    selector: 'app-turret-group',
    standalone: true,
    templateUrl: './turret-group.html',
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
export class TurretGroupComponent implements OnInit {
    items: TurretGroup[] = [];
    allExtensions: Extension[] = [];
    isLoading = false;
    showModal = false;
    modalMode: 'create' | 'edit' = 'create';
    formData: TurretGroup = { name: '', description: '', is_active: true, members: [] };
    search = '';

    // Member selection helper
    selectedMembersMap: { [key: string]: boolean } = {};

    private http = inject(HttpClient);

    ngOnInit() {
        this.loadItems();
        this.loadExtensions();
    }

    get filteredItems(): TurretGroup[] {
        if (!this.search) return this.items;
        const s = this.search.toLowerCase();
        return this.items.filter(item =>
            item.name.toLowerCase().includes(s)
        );
    }

    loadExtensions() {
        // Fetch all users/extensions that can be members
        // Using existing users endpoint or we can use extensions endpoint if available
        // Assuming we want extensions list. Let's try to get from extensions endpoint
        this.http.get<any>(`${environment.apiUrl}/v1/dropdowns?type=extensions`).subscribe({
            next: (res) => {
                this.allExtensions = res.data || [];
            }
        });
    }

    loadItems() {
        this.isLoading = true;
        this.http.get<any>(`${environment.apiUrl}/v1/turret-groups`).subscribe({
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
        this.formData = { name: '', description: '', is_active: true, members: [] };
        // Reset selection map
        this.selectedMembersMap = {};
        this.showModal = true;
    }

    openEditModal(item: TurretGroup) {
        this.modalMode = 'edit';
        this.formData = { ...item };
        // Map members to selection map
        this.selectedMembersMap = {};
        if (item.members && Array.isArray(item.members)) {
            item.members.forEach(ext => this.selectedMembersMap[ext] = true);
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

        // Convert selection map back to array
        this.formData.members = Object.keys(this.selectedMembersMap).filter(k => this.selectedMembersMap[k]);

        const url = this.modalMode === 'create'
            ? `${environment.apiUrl}/v1/turret-groups`
            : `${environment.apiUrl}/v1/turret-groups/${this.formData.id}`;

        const method = this.modalMode === 'create' ? 'post' : 'put';

        this.http.request(method, url, { body: this.formData }).subscribe({
            next: () => {
                Swal.fire('Success', 'Group saved successfully', 'success');
                this.closeModal();
                this.loadItems();
            },
            error: (err) => {
                Swal.fire('Error', err.error?.error || 'Failed to save group', 'error');
            }
        });
    }

    copyRecord(item: TurretGroup) {
        Swal.fire({
            title: 'Duplicate Group?',
            text: `Create a copy of "${item.name}"?`,
            icon: 'question',
            showCancelButton: true,
            confirmButtonText: 'Yes, duplicate it!'
        }).then((result) => {
            if (result.isConfirmed) {
                // Fetch full details first to ensure we get members
                this.http.get<TurretGroup>(`${environment.apiUrl}/v1/turret-groups/${item.id}`).subscribe({
                    next: (fullItem) => {
                        const copy: TurretGroup = {
                            name: `${item.name} (Copy)`,
                            description: item.description,
                            is_active: item.is_active,
                            members: fullItem.members || [] // Clone members
                        };

                        this.http.post<any>(`${environment.apiUrl}/v1/turret-groups`, copy).subscribe({
                            next: () => {
                                this.loadItems();
                                Swal.fire('Success', 'Group duplicated successfully', 'success');
                            },
                            error: (err) => {
                                Swal.fire('Error', 'Failed to duplicate group', 'error');
                            }
                        });
                    },
                    error: () => {
                        Swal.fire('Error', 'Failed to fetch original group details', 'error');
                    }
                });
            }
        });
    }

    deleteRecord(item: TurretGroup) {
        Swal.fire({
            title: 'Delete Group?',
            text: `Are you sure you want to delete "${item.name}"?`,
            icon: 'warning',
            showCancelButton: true,
            confirmButtonText: 'Yes, delete it!'
        }).then((result) => {
            if (result.isConfirmed) {
                this.http.delete<any>(`${environment.apiUrl}/v1/turret-groups/${item.id}`).subscribe({
                    next: () => {
                        this.loadItems();
                        Swal.fire('Deleted!', 'Group deleted.', 'success');
                    },
                    error: () => {
                        Swal.fire('Error', 'Failed to delete group', 'error');
                    }
                });
            }
        });
    }
}
