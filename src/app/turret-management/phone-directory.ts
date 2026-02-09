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

interface PhoneDirectory {
    id?: number;
    name: string;
    company?: string;
    phones: string[];
    email?: string;
    notes?: string;
    is_active: boolean;
}

@Component({
    selector: 'app-phone-directory',
    standalone: true,
    templateUrl: './phone-directory.html',
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
export class PhoneDirectoryComponent implements OnInit {
    items: PhoneDirectory[] = [];
    isLoading = false;
    showModal = false;
    modalMode: 'create' | 'edit' = 'create';
    formData: PhoneDirectory = { name: '', company: '', phones: [''], email: '', notes: '', is_active: true };
    search = '';

    private http = inject(HttpClient);

    ngOnInit() {
        this.loadItems();
    }

    get filteredItems(): PhoneDirectory[] {
        if (!this.search) return this.items;
        const s = this.search.toLowerCase();
        return this.items.filter(item =>
            item.name.toLowerCase().includes(s) ||
            (item.company && item.company.toLowerCase().includes(s)) ||
            item.phones.some(p => p.includes(s))
        );
    }

    loadItems() {
        this.isLoading = true;
        this.http.get<any>(`${environment.apiUrl}/v1/phone-directories`).subscribe({
            next: (res) => {
                this.items = (res.data || []).map((item: any) => ({
                    ...item,
                    phones: typeof item.phones === 'string' ? JSON.parse(item.phones) : item.phones
                }));
                this.isLoading = false;
            },
            error: () => {
                this.isLoading = false;
            }
        });
    }

    openCreateModal() {
        this.modalMode = 'create';
        this.formData = { name: '', company: '', phones: [''], email: '', notes: '', is_active: true };
        this.showModal = true;
    }

    openEditModal(item: PhoneDirectory) {
        this.modalMode = 'edit';
        this.formData = { ...item, phones: [...item.phones] };
        this.showModal = true;
    }

    closeModal() {
        this.showModal = false;
    }

    addPhone() {
        this.formData.phones.push('');
    }

    removePhone(index: number) {
        if (this.formData.phones.length > 1) {
            this.formData.phones.splice(index, 1);
        }
    }

    trackByIndex(index: number): number {
        return index;
    }

    saveRecord() {
        if (!this.formData.name) {
            Swal.fire('Error', 'Name is required', 'error');
            return;
        }

        // Filter empty phones
        const cleanPhones = this.formData.phones.filter(p => p.trim());
        if (cleanPhones.length === 0) {
            Swal.fire('Error', 'At least one phone number is required', 'error');
            return;
        }

        const payload = {
            ...this.formData,
            phones: JSON.stringify(cleanPhones)
        };

        const url = this.modalMode === 'create'
            ? `${environment.apiUrl}/v1/phone-directories`
            : `${environment.apiUrl}/v1/phone-directories/${this.formData.id}`;

        const method = this.modalMode === 'create' ? 'post' : 'put';

        this.http.request(method, url, { body: payload }).subscribe({
            next: () => {
                Swal.fire('Success', 'Contact saved successfully', 'success');
                this.closeModal();
                this.loadItems();
            },
            error: (err) => {
                Swal.fire('Error', err.error?.error || 'Failed to save contact', 'error');
            }
        });
    }

    copyRecord(item: PhoneDirectory) {
        Swal.fire({
            title: 'Duplicate Contact?',
            text: `Create a copy of "${item.name}"?`,
            icon: 'question',
            showCancelButton: true,
            confirmButtonText: 'Yes, duplicate!'
        }).then((result) => {
            if (result.isConfirmed) {
                const copy = {
                    name: `${item.name} (Copy)`,
                    company: item.company,
                    phones: JSON.stringify(item.phones),
                    email: item.email,
                    notes: item.notes,
                    is_active: item.is_active
                };

                this.http.post<any>(`${environment.apiUrl}/v1/phone-directories`, copy).subscribe({
                    next: () => {
                        this.loadItems();
                        Swal.fire('Success', 'Contact duplicated', 'success');
                    },
                    error: () => {
                        Swal.fire('Error', 'Failed to duplicate', 'error');
                    }
                });
            }
        });
    }

    deleteRecord(item: PhoneDirectory) {
        Swal.fire({
            title: 'Delete Contact?',
            text: `Delete "${item.name}"?`,
            icon: 'warning',
            showCancelButton: true,
            confirmButtonText: 'Yes, delete!'
        }).then((result) => {
            if (result.isConfirmed) {
                this.http.delete<any>(`${environment.apiUrl}/v1/phone-directories/${item.id}`).subscribe({
                    next: () => {
                        this.loadItems();
                        Swal.fire('Deleted!', 'Contact deleted.', 'success');
                    },
                    error: () => {
                        Swal.fire('Error', 'Failed to delete', 'error');
                    }
                });
            }
        });
    }
}
