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

interface User {
    id?: number;
    name: string;
    email: string;
    password?: string;
    role: string;
    is_active: boolean;
    last_login?: string;
    created_at?: string;
    profile_image?: string;
}

@Component({
    selector: 'app-cms-users',
    standalone: true,
    templateUrl: './cms-users.html',
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
export class CmsUsersComponent implements OnInit {
    items: User[] = [];
    isLoading = false;
    showModal = false;
    modalMode: 'create' | 'edit' = 'create';
    formData: User = { name: '', email: '', password: '', role: 'viewer', is_active: true };
    search = '';
    imageBaseUrl = environment.imageBaseUrl;

    private http = inject(HttpClient);
    private route = inject(ActivatedRoute);
    private router = inject(Router);

    ngOnInit() {
        this.loadItems();

        // Handle auto-edit modal on initialization
        this.route.queryParams.subscribe(params => {
            if (params['edit_self'] && localStorage.getItem('userId')) {
                const checkInterval = setInterval(() => {
                    if (this.items.length > 0) {
                        const myId = Number(localStorage.getItem('userId'));
                        const me = this.items.find(u => u.id === myId);
                        if (me) {
                            this.openEditModal(me);
                        }
                        clearInterval(checkInterval);
                    }
                }, 100);

                // Safety timeout
                setTimeout(() => clearInterval(checkInterval), 3000);
            }
        });
    }

    get filteredItems(): User[] {
        if (!this.search) return this.items;
        const s = this.search.toLowerCase();
        return this.items.filter(item =>
            item.name.toLowerCase().includes(s) ||
            item.email.toLowerCase().includes(s) ||
            item.role.toLowerCase().includes(s)
        );
    }

    onFileSelected(event: any) {
        const file = event.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = (e: any) => {
                this.formData.profile_image = e.target.result;
            };
            reader.readAsDataURL(file);
        }
    }

    loadItems() {
        this.isLoading = true;
        this.http.get<any>(`${environment.apiUrl}/v1/users`).subscribe({
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
        this.formData = { name: '', email: '', password: '', role: 'viewer', is_active: true };
        this.showModal = true;
    }

    openEditModal(item: User) {
        this.modalMode = 'edit';
        this.formData = { ...item, password: '' };
        this.showModal = true;
    }

    copyRecord(item: User) {
        this.modalMode = 'create';
        this.formData = { ...item, id: undefined, email: item.email + '.copy', password: '' };
        this.showModal = true;
    }

    closeModal() {
        this.showModal = false;
    }

    saveRecord() {
        if (!this.formData.name || !this.formData.email) {
            Swal.fire('Error', 'Name and email are required', 'error');
            return;
        }

        if (this.modalMode === 'create') {
            if (!this.formData.password) {
                Swal.fire('Error', 'Password is required for new user', 'error');
                return;
            }
            this.http.post<any>(`${environment.apiUrl}/v1/users`, this.formData).subscribe({
                next: () => {
                    Swal.fire('Success', 'User created successfully', 'success');
                    this.closeModal();
                    this.loadItems();
                },
                error: (err) => {
                    Swal.fire('Error', err.error?.error || 'Failed to create user', 'error');
                }
            });
        } else {
            const payload = { ...this.formData };
            if (!payload.password) delete payload.password;
            this.http.put<any>(`${environment.apiUrl}/v1/users/${this.formData.id}`, payload).subscribe({
                next: (res) => {
                    Swal.fire('Success', 'User updated successfully', 'success');

                    // Update header if user updated their own profile
                    if (String(this.formData.id) === localStorage.getItem('userId')) {
                        localStorage.setItem('userProfileImage', res.data.profile_image || '');
                        // Dispatch event to notify other components (like Header)
                        window.dispatchEvent(new Event('storage'));
                    }

                    this.closeModal();

                    // Clear query params to prevent auto-reopening, then reload data
                    this.router.navigate([], {
                        queryParams: { edit_self: null },
                        queryParamsHandling: 'merge'
                    }).then(() => {
                        this.loadItems();
                    });
                },
                error: (err) => {
                    Swal.fire('Error', err.error?.error || 'Failed to update user', 'error');
                }
            });
        }
    }

    deleteRecord(item: User) {
        Swal.fire({
            title: 'Delete User?',
            text: `Are you sure you want to delete "${item.name}"?`,
            icon: 'warning',
            showCancelButton: true,
            confirmButtonText: 'Yes, delete it!',
            cancelButtonText: 'Cancel'
        }).then((result) => {
            if (result.isConfirmed) {
                this.http.delete<any>(`${environment.apiUrl}/v1/users/${item.id}`).subscribe({
                    next: () => {
                        Swal.fire('Deleted!', 'User has been deleted.', 'success');
                        this.loadItems();
                    },
                    error: () => {
                        Swal.fire('Error', 'Failed to delete user', 'error');
                    }
                });
            }
        });
    }

    getRoleBadgeClass(role: string): string {
        switch (role) {
            case 'admin': return 'badge-outline-danger';
            case 'operator': return 'badge-outline-warning';
            default: return 'badge-outline-info';
        }
    }
}
