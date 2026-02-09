import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { DataTableModule } from '@bhplugin/ng-datatable';
import { OrganizationService, Company } from '../services/organization.service';
import { IconCircleCheckComponent } from '../../shared/icon/icon-circle-check';
import Swal from 'sweetalert2';

@Component({
    selector: 'app-company-list',
    templateUrl: './company-list.html',
    imports: [CommonModule, FormsModule, RouterModule, DataTableModule, IconCircleCheckComponent],
})
export class CompanyListComponent implements OnInit {
    loading = false;
    search = '';
    showModal = false;
    modalMode: 'create' | 'edit' = 'create';
    editingId: number | null = null;

    // Form data
    formData = {
        name: '',
        code: '',
        active: true,
        contactPerson: '',
        email: '',
        phone: '',
        address: '',
    };

    cols = [
        { field: 'code', title: 'Code', isUnique: true },
        { field: 'name', title: 'Company Name' },
        { field: 'contact_person', title: 'Contact' },
        { field: 'phone', title: 'Phone' },
        { field: 'head_offices_count', title: 'HO', headerClass: 'justify-center', cellClass: 'justify-center' },
        { field: 'branches_count', title: 'Branches', headerClass: 'justify-center', cellClass: 'justify-center' },
        { field: 'is_active', title: 'Active', sort: false, headerClass: 'justify-center', cellClass: 'justify-center' },
        { field: 'actions', title: '', sort: false, headerClass: '!text-center', cellClass: '!text-center' },
    ];

    rows: any[] = [];
    filteredRows: any[] = [];

    constructor(private organizationService: OrganizationService) { }

    ngOnInit(): void {
        this.loadData();
    }

    loadData() {
        this.loading = true;
        this.organizationService.getCompanies({ search: this.search }).subscribe({
            next: (response) => {
                this.rows = response.data.map((c) => ({
                    id: c.id,
                    code: c.code || '-',
                    name: c.name,
                    contact_person: c.contact_person || '-',
                    phone: c.phone || '-',
                    email: c.email || '',
                    address: c.address || '',
                    head_offices_count: c.head_offices_count || 0,
                    branches_count: c.branches_count || 0,
                    is_active: c.is_active,
                }));
                this.filteredRows = [...this.rows];
                this.loading = false;
            },
            error: (err) => {
                console.error('Error loading companies:', err);
                this.rows = [];
                this.filteredRows = [];
                this.loading = false;
            },
        });
    }

    onSearch() {
        this.loadData();
    }

    openModal(mode: 'create' | 'edit', item?: any) {
        this.modalMode = mode;
        if (mode === 'edit' && item) {
            this.editingId = item.id;
            this.formData = {
                name: item.name || '',
                code: item.code === '-' ? '' : item.code,
                active: item.is_active ?? true,
                contactPerson: item.contact_person === '-' ? '' : item.contact_person,
                email: item.email || '',
                phone: item.phone === '-' ? '' : item.phone,
                address: item.address || '',
            };
        } else {
            this.editingId = null;
            this.resetForm();
        }
        this.showModal = true;
    }

    closeModal() {
        this.showModal = false;
        this.resetForm();
    }

    resetForm() {
        this.formData = {
            name: '',
            code: '',
            active: true,
            contactPerson: '',
            email: '',
            phone: '',
            address: '',
        };
        this.editingId = null;
    }

    copyRecord(item: any) {
        this.modalMode = 'create';
        this.editingId = null;
        this.formData = {
            name: (item.name || '') + ' - Copy',
            code: (item.code === '-' ? '' : item.code) + '-copy',
            active: item.is_active ?? true,
            contactPerson: item.contact_person === '-' ? '' : item.contact_person,
            email: item.email || '',
            phone: item.phone === '-' ? '' : item.phone,
            address: item.address || '',
        };
        this.showModal = true;
    }

    saveRecord() {
        const payload: Company = {
            name: this.formData.name,
            code: this.formData.code,
            is_active: this.formData.active,
            contact_person: this.formData.contactPerson,
            email: this.formData.email,
            phone: this.formData.phone,
            address: this.formData.address,
        };

        if (this.modalMode === 'edit' && this.editingId) {
            this.organizationService.updateCompany(this.editingId, payload).subscribe({
                next: () => {
                    Swal.fire('Success', 'Company updated successfully', 'success');
                    this.closeModal();
                    this.loadData();
                },
                error: (error) => {
                    console.error('Failed to update company:', error);
                    Swal.fire('Error', 'Failed to update company', 'error');
                },
            });
        } else {
            this.organizationService.createCompany(payload).subscribe({
                next: () => {
                    Swal.fire('Success', 'Company created successfully', 'success');
                    this.closeModal();
                    this.loadData();
                },
                error: (error) => {
                    console.error('Failed to create company:', error);
                    Swal.fire('Error', 'Failed to create company', 'error');
                },
            });
        }
    }

    deleteCompany(row: any) {
        Swal.fire({
            title: 'Delete Company?',
            text: 'Are you sure you want to delete this company?',
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#d33',
            cancelButtonColor: '#3085d6',
            confirmButtonText: 'Yes, delete it!'
        }).then((result) => {
            if (result.isConfirmed) {
                this.organizationService.deleteCompany(row.id).subscribe({
                    next: () => {
                        Swal.fire('Deleted!', 'Company has been deleted.', 'success');
                        this.loadData();
                    },
                    error: (err) => {
                        console.error('Error deleting company:', err);
                        Swal.fire('Error', 'Failed to delete company', 'error');
                    },
                });
            }
        });
    }
}
