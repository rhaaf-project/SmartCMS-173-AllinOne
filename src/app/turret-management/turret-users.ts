import { Component, inject, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { Router, RouterModule, ActivatedRoute } from '@angular/router';
import { Store } from '@ngrx/store';
import { toggleAnimation } from '../shared/animations';
import { environment } from '../../environments/environment';
import { IconPencilComponent } from '../shared/icon/icon-pencil';
import { IconTrashLinesComponent } from '../shared/icon/icon-trash-lines';
import { IconCopyComponent } from '../shared/icon/icon-copy';
import { IconCircleCheckComponent } from '../shared/icon/icon-circle-check';
import Swal from 'sweetalert2';

interface TurretUser {
    id?: number;
    name: string;
    password?: string;
    use_ext: string;
    is_active: boolean;
    last_login?: string;
    created_at?: string;
    extension_data?: { id: number; extension: string; name: string };
}

interface Extension {
    id: number;
    name: string;
}

interface PhonebookEntry {
    id?: number;
    turret_user_id?: number;
    name: string;
    phone: string;
    company?: string;
    email?: string;
    notes?: string;
    is_favourite: boolean;
}

@Component({
    selector: 'app-turret-users',
    standalone: true,
    templateUrl: './turret-users.html',
    animations: [toggleAnimation],
    imports: [
        CommonModule,
        FormsModule,
        RouterModule,
        IconPencilComponent,
        IconTrashLinesComponent,
        IconCopyComponent,
        IconCircleCheckComponent,
    ],
})
export class TurretUsersComponent implements OnInit {
    items: TurretUser[] = [];
    extensions: Extension[] = [];
    isLoading = false;
    showModal = false;
    modalMode: 'create' | 'edit' = 'create';
    formData: TurretUser = { name: '', password: '', use_ext: '', is_active: true };
    search = '';

    // Phonebook Modal State
    showPhonebookModal = false;
    phonebookUser: TurretUser | null = null;
    phonebookItems: PhonebookEntry[] = [];
    phonebookLoading = false;
    phonebookFormMode: 'create' | 'edit' = 'create';
    phonebookFormData: PhonebookEntry = { name: '', phone: '', company: '', email: '', notes: '', is_favourite: false };
    showPhonebookForm = false;
    phonebookSortColumn: 'favourite' | 'name' | 'phone' | 'company' = 'favourite';
    phonebookSortDir: 'asc' | 'desc' = 'desc';  // desc = favourite first

    // Toggle sort when clicking column header
    sortPhonebook(column: 'favourite' | 'name' | 'phone' | 'company') {
        if (this.phonebookSortColumn === column) {
            this.phonebookSortDir = this.phonebookSortDir === 'asc' ? 'desc' : 'asc';
        } else {
            this.phonebookSortColumn = column;
            this.phonebookSortDir = column === 'favourite' ? 'desc' : 'asc';
        }
    }

    // Get sorted phonebook items
    get sortedPhonebookItems(): PhonebookEntry[] {
        return [...this.phonebookItems].sort((a, b) => {
            let cmp = 0;
            switch (this.phonebookSortColumn) {
                case 'favourite':
                    cmp = (a.is_favourite === b.is_favourite) ? 0 : (a.is_favourite ? -1 : 1);
                    break;
                case 'name':
                    cmp = (a.name || '').localeCompare(b.name || '');
                    break;
                case 'phone':
                    cmp = (a.phone || '').localeCompare(b.phone || '');
                    break;
                case 'company':
                    cmp = (a.company || '').localeCompare(b.company || '');
                    break;
            }
            return this.phonebookSortDir === 'asc' ? cmp : -cmp;
        });
    }

    private http = inject(HttpClient);
    private route = inject(ActivatedRoute);
    private router = inject(Router);

    ngOnInit() {
        this.loadItems();
        this.loadExtensions();
    }

    get filteredItems(): TurretUser[] {
        if (!this.search) return this.items;
        const s = this.search.toLowerCase();
        return this.items.filter(item =>
            item.name.toLowerCase().includes(s) ||
            item.use_ext?.toLowerCase().includes(s)
        );
    }

    loadExtensions() {
        this.http.get<any>(`${environment.apiUrl}/v1/dropdowns?type=extensions`).subscribe({
            next: (res) => {
                this.extensions = res.data || [];
            },
            error: () => {
                console.error('Failed to load extensions');
            }
        });
    }

    loadItems() {
        this.isLoading = true;
        this.http.get<any>(`${environment.apiUrl}/v1/turret-users`).subscribe({
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
        this.formData = { name: '', password: '', use_ext: '', is_active: true };
        this.showModal = true;
    }

    openEditModal(item: TurretUser) {
        this.modalMode = 'edit';
        this.formData = { ...item, password: '' };
        this.showModal = true;
    }

    copyRecord(item: TurretUser) {
        this.modalMode = 'create';
        this.formData = { ...item, id: undefined, name: item.name + '_copy', password: '' };
        this.showModal = true;
    }

    closeModal() {
        this.showModal = false;
    }

    saveRecord() {
        if (!this.formData.name) {
            Swal.fire('Error', 'Username is required', 'error');
            return;
        }

        if (this.modalMode === 'create') {
            if (!this.formData.password) {
                Swal.fire('Error', 'Password is required for new user', 'error');
                return;
            }
            this.http.post<any>(`${environment.apiUrl}/v1/turret-users`, this.formData).subscribe({
                next: () => {
                    Swal.fire('Success', 'Turret user created successfully', 'success');
                    this.closeModal();
                    this.loadItems();
                },
                error: (err) => {
                    Swal.fire('Error', err.error?.error || 'Failed to create turret user', 'error');
                }
            });
        } else {
            const payload = { ...this.formData };
            if (!payload.password) delete payload.password;
            this.http.put<any>(`${environment.apiUrl}/v1/turret-users/${this.formData.id}`, payload).subscribe({
                next: () => {
                    Swal.fire('Success', 'Turret user updated successfully', 'success');
                    this.closeModal();
                    this.loadItems();
                },
                error: (err) => {
                    Swal.fire('Error', err.error?.error || 'Failed to update turret user', 'error');
                }
            });
        }
    }

    deleteRecord(item: TurretUser) {
        Swal.fire({
            title: 'Delete Turret User?',
            text: `Are you sure you want to delete "${item.name}"?`,
            icon: 'warning',
            showCancelButton: true,
            confirmButtonText: 'Yes, delete it!',
            cancelButtonText: 'Cancel'
        }).then((result) => {
            if (result.isConfirmed) {
                this.http.delete<any>(`${environment.apiUrl}/v1/turret-users/${item.id}`).subscribe({
                    next: () => {
                        Swal.fire('Deleted!', 'Turret user has been deleted.', 'success');
                        this.loadItems();
                    },
                    error: () => {
                        Swal.fire('Error', 'Failed to delete turret user', 'error');
                    }
                });
            }
        });
    }

    // ===== PHONEBOOK METHODS =====

    openPhonebook(user: TurretUser) {
        this.phonebookUser = user;
        this.showPhonebookModal = true;
        this.showPhonebookForm = false;
        this.loadPhonebook();
    }

    closePhonebook() {
        this.showPhonebookModal = false;
        this.phonebookUser = null;
        this.phonebookItems = [];
    }

    loadPhonebook() {
        if (!this.phonebookUser?.id) return;
        this.phonebookLoading = true;
        this.http.get<any>(`${environment.apiUrl}/v1/turret-user-phonebooks?turret_user_id=${this.phonebookUser.id}`).subscribe({
            next: (res) => {
                this.phonebookItems = res.data || [];
                this.phonebookLoading = false;
            },
            error: () => {
                this.phonebookLoading = false;
            }
        });
    }

    openAddPhonebookEntry() {
        this.phonebookFormMode = 'create';
        this.phonebookFormData = { name: '', phone: '', company: '', email: '', notes: '', is_favourite: false };
        this.showPhonebookForm = true;
    }

    openEditPhonebookEntry(entry: PhonebookEntry) {
        this.phonebookFormMode = 'edit';
        this.phonebookFormData = { ...entry };
        this.showPhonebookForm = true;
    }

    closePhonebookForm() {
        this.showPhonebookForm = false;
    }

    savePhonebookEntry() {
        if (!this.phonebookFormData.name || !this.phonebookFormData.phone) {
            Swal.fire('Error', 'Name and Phone are required', 'error');
            return;
        }

        const payload = {
            ...this.phonebookFormData,
            turret_user_id: this.phonebookUser?.id
        };

        if (this.phonebookFormMode === 'create') {
            this.http.post<any>(`${environment.apiUrl}/v1/turret-user-phonebooks`, payload).subscribe({
                next: () => {
                    Swal.fire('Success', 'Contact added', 'success');
                    this.closePhonebookForm();
                    this.loadPhonebook();
                },
                error: (err) => {
                    Swal.fire('Error', err.error?.error || 'Failed to add contact', 'error');
                }
            });
        } else {
            this.http.put<any>(`${environment.apiUrl}/v1/turret-user-phonebooks/${this.phonebookFormData.id}`, payload).subscribe({
                next: () => {
                    Swal.fire('Success', 'Contact updated', 'success');
                    this.closePhonebookForm();
                    this.loadPhonebook();
                },
                error: (err) => {
                    Swal.fire('Error', err.error?.error || 'Failed to update contact', 'error');
                }
            });
        }
    }

    deletePhonebookEntry(entry: PhonebookEntry) {
        Swal.fire({
            title: 'Delete Contact?',
            text: `Delete "${entry.name}"?`,
            icon: 'warning',
            showCancelButton: true,
            confirmButtonText: 'Yes, delete!'
        }).then((result) => {
            if (result.isConfirmed) {
                this.http.delete<any>(`${environment.apiUrl}/v1/turret-user-phonebooks/${entry.id}`).subscribe({
                    next: () => {
                        Swal.fire('Deleted!', 'Contact deleted.', 'success');
                        this.loadPhonebook();
                    },
                    error: () => {
                        Swal.fire('Error', 'Failed to delete contact', 'error');
                    }
                });
            }
        });
    }

    toggleFavourite(entry: PhonebookEntry) {
        const newValue = !entry.is_favourite;
        this.http.put<any>(`${environment.apiUrl}/v1/turret-user-phonebooks/${entry.id}`, {
            ...entry,
            is_favourite: newValue
        }).subscribe({
            next: () => {
                entry.is_favourite = newValue;
            }
        });
    }

    copyPhonebookEntry(entry: PhonebookEntry) {
        const copy = {
            name: `${entry.name} (Copy)`,
            phone: entry.phone,
            company: entry.company,
            email: entry.email,
            notes: entry.notes,
            is_favourite: false,
            turret_user_id: this.phonebookUser?.id
        };
        this.http.post<any>(`${environment.apiUrl}/v1/turret-user-phonebooks`, copy).subscribe({
            next: () => {
                Swal.fire('Success', 'Contact duplicated', 'success');
                this.loadPhonebook();
            },
            error: () => {
                Swal.fire('Error', 'Failed to duplicate contact', 'error');
            }
        });
    }
}
