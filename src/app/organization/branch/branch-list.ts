import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { DataTableModule } from '@bhplugin/ng-datatable';
import { OrganizationService, Company, HeadOffice, Branch } from '../services/organization.service';
import { environment } from '../../../environments/environment';
import { IconCircleCheckComponent } from '../../shared/icon/icon-circle-check';
import Swal from 'sweetalert2';

@Component({
    selector: 'app-branch-list',
    templateUrl: './branch-list.html',
    imports: [CommonModule, FormsModule, RouterModule, DataTableModule, IconCircleCheckComponent],
})
export class BranchListComponent implements OnInit {
    loading = false;
    search = '';
    showModal = false;
    modalMode: 'create' | 'edit' = 'create';
    editingId: number | null = null;
    contactExpanded = false;

    companies: Company[] = [];
    filteredHeadOffices: HeadOffice[] = [];
    callServers: any[] = [];

    private http = inject(HttpClient);

    formData = {
        companyId: null as number | null,
        headOfficeId: null as number | null,
        callServerId: null as number | null,
        name: '',
        code: '',
        active: true,
        country: 'Indonesia',
        province: '',
        city: '',
        district: '',
        address: '',
        contactName: '',
        contactPhone: '',
        description: '',
    };

    cols = [
        { field: 'company', title: 'Company' },
        { field: 'code', title: 'Code' },
        { field: 'name', title: 'Branch Name' },
        { field: 'headOffice', title: 'HO' },
        { field: 'city', title: 'City' },
        { field: 'district', title: 'District' },
        { field: 'callServer', title: 'Call Server' },
        { field: 'active', title: 'Active', sort: false, headerClass: 'justify-center', cellClass: 'justify-center' },
        { field: 'actions', title: '', sort: false, headerClass: '!text-center', cellClass: '!text-center' },
    ];

    rows: any[] = [];
    filteredRows: any[] = [];

    constructor(private organizationService: OrganizationService) { }

    ngOnInit(): void {
        this.loadData();
        this.loadCompanies();
        this.loadCallServers();
    }

    loadData() {
        this.loading = true;
        this.organizationService.getBranches({ search: this.search }).subscribe({
            next: (response) => {
                this.rows = (response.data || []).map((b: any) => ({
                    id: b.id,
                    company: b.customer?.name || '-',
                    company_id: b.customer_id,
                    code: b.code || '-',
                    name: b.name,
                    headOffice: b.head_office?.name || '-',
                    head_office_id: b.head_office_id,
                    city: b.city || '-',
                    district: b.district || '-',
                    callServer: b.call_server?.name || '-',
                    call_server_id: b.call_server_id,
                    country: b.country || '',
                    province: b.province || '',
                    address: b.address || '',
                    contact_name: b.contact_name || '',
                    contact_phone: b.contact_phone || '',
                    description: b.description || '',
                    active: b.is_active,
                }));
                this.filteredRows = [...this.rows];
                this.loading = false;
            },
            error: (err) => {
                console.error('Failed to load branches:', err);
                this.rows = [];
                this.filteredRows = [];
                this.loading = false;
            }
        });
    }

    loadCompanies() {
        this.organizationService.getCompanies().subscribe({
            next: (response) => {
                this.companies = response.data || [];
            },
            error: (err) => console.error('Failed to load companies:', err)
        });
    }

    loadHeadOffices(customerId: number) {
        this.organizationService.getHeadOffices({ customer_id: customerId }).subscribe({
            next: (response) => {
                this.filteredHeadOffices = response.data || [];
            },
            error: (err) => console.error('Failed to load head offices:', err)
        });
    }

    loadCallServers() {
        const apiUrl = `${environment.apiUrl}/v1/call-servers`;
        this.http.get<any>(apiUrl).subscribe({
            next: (response) => {
                this.callServers = response.data || [];
            },
            error: (err) => console.error('Failed to load call servers:', err)
        });
    }

    onSearch() {
        this.loadData();
    }

    onCompanyChange() {
        if (this.formData.companyId) {
            this.loadHeadOffices(this.formData.companyId);
        } else {
            this.filteredHeadOffices = [];
        }
        this.formData.headOfficeId = null;
    }

    openModal(mode: 'create' | 'edit', item?: any) {
        this.modalMode = mode;
        this.contactExpanded = false;
        if (mode === 'edit' && item) {
            this.editingId = item.id;
            this.formData = {
                companyId: item.company_id,
                headOfficeId: item.head_office_id,
                callServerId: item.call_server_id,
                name: item.name || '',
                code: item.code === '-' ? '' : item.code,
                active: item.active ?? true,
                country: item.country || 'Indonesia',
                province: item.province || '',
                city: item.city === '-' ? '' : item.city,
                district: item.district === '-' ? '' : item.district,
                address: item.address || '',
                contactName: item.contact_name || '',
                contactPhone: item.contact_phone || '',
                description: item.description || '',
            };
            if (this.formData.companyId) {
                this.loadHeadOffices(this.formData.companyId);
            }
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
            companyId: null,
            headOfficeId: null,
            callServerId: null,
            name: '',
            code: '',
            active: true,
            country: 'Indonesia',
            province: '',
            city: '',
            district: '',
            address: '',
            contactName: '',
            contactPhone: '',
            description: '',
        };
        this.filteredHeadOffices = [];
        this.editingId = null;
    }

    copyRecord(item: any) {
        this.modalMode = 'create';
        this.editingId = null;
        this.contactExpanded = false;
        this.formData = {
            companyId: item.company_id,
            headOfficeId: item.head_office_id,
            callServerId: item.call_server_id,
            name: (item.name || '') + ' - Copy',
            code: (item.code === '-' ? '' : item.code) + '-copy',
            active: item.active ?? true,
            country: item.country || 'Indonesia',
            province: item.province || '',
            city: item.city === '-' ? '' : item.city,
            district: item.district === '-' ? '' : item.district,
            address: item.address || '',
            contactName: item.contact_name || '',
            contactPhone: item.contact_phone || '',
            description: item.description || '',
        };
        if (this.formData.companyId) {
            this.loadHeadOffices(this.formData.companyId);
        }
        this.showModal = true;
    }

    toggleContact() {
        this.contactExpanded = !this.contactExpanded;
    }

    saveRecord() {
        const payload: Branch = {
            customer_id: this.formData.companyId || undefined,
            head_office_id: this.formData.headOfficeId || undefined,
            call_server_id: this.formData.callServerId || undefined,
            name: this.formData.name,
            code: this.formData.code,
            is_active: this.formData.active,
            country: this.formData.country,
            province: this.formData.province,
            city: this.formData.city,
            district: this.formData.district,
            address: this.formData.address,
            contact_name: this.formData.contactName,
            contact_phone: this.formData.contactPhone,
            description: this.formData.description,
        };

        if (this.modalMode === 'edit' && this.editingId) {
            this.organizationService.updateBranch(this.editingId, payload).subscribe({
                next: () => {
                    Swal.fire('Success', 'Branch updated successfully', 'success');
                    this.closeModal();
                    this.loadData();
                },
                error: (err) => {
                    console.error('Failed to update branch:', err);
                    Swal.fire('Error', 'Failed to update branch', 'error');
                }
            });
        } else {
            this.organizationService.createBranch(payload).subscribe({
                next: () => {
                    Swal.fire('Success', 'Branch created successfully', 'success');
                    this.closeModal();
                    this.loadData();
                },
                error: (err) => {
                    console.error('Failed to create branch:', err);
                    Swal.fire('Error', 'Failed to create branch', 'error');
                }
            });
        }
    }

    deleteBranch(row: any) {
        Swal.fire({
            title: 'Delete Branch?',
            text: 'Are you sure you want to delete this branch?',
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#d33',
            cancelButtonColor: '#3085d6',
            confirmButtonText: 'Yes, delete it!'
        }).then((result) => {
            if (result.isConfirmed) {
                this.organizationService.deleteBranch(row.id).subscribe({
                    next: () => {
                        Swal.fire('Deleted!', 'Branch has been deleted.', 'success');
                        this.loadData();
                    },
                    error: (err) => {
                        console.error('Failed to delete branch:', err);
                        Swal.fire('Error', 'Failed to delete branch', 'error');
                    }
                });
            }
        });
    }
}
