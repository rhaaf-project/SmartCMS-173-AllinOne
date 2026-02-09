import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { DataTableModule } from '@bhplugin/ng-datatable';
import { OrganizationService, Company, Branch, SubBranch } from '../services/organization.service';
import { environment } from '../../../environments/environment';
import { IconCircleCheckComponent } from '../../shared/icon/icon-circle-check';
import Swal from 'sweetalert2';

@Component({
    selector: 'app-sub-branch-list',
    templateUrl: './sub-branch-list.html',
    imports: [CommonModule, FormsModule, RouterModule, DataTableModule, IconCircleCheckComponent],
})
export class SubBranchListComponent implements OnInit {
    loading = false;
    search = '';
    showModal = false;
    modalMode: 'create' | 'edit' = 'create';
    editingId: number | null = null;
    contactExpanded = false;

    companies: Company[] = [];
    filteredBranches: Branch[] = [];
    availableCallServers: any[] = [];

    private http = inject(HttpClient);

    formData = {
        companyId: null as number | null,
        parentBranchId: null as number | null,
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
        { field: 'name', title: 'Sub Branch Name' },
        { field: 'parentBranch', title: 'Parent Branch' },
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
        this.organizationService.getSubBranches({ search: this.search }).subscribe({
            next: (response) => {
                this.rows = (response.data || []).map((sb: any) => ({
                    id: sb.id,
                    company: sb.customer?.name || '-',
                    company_id: sb.customer_id,
                    code: sb.code || '-',
                    name: sb.name,
                    parentBranch: sb.branch?.name || '-',
                    branch_id: sb.branch_id,
                    city: sb.city || '-',
                    district: sb.district || '-',
                    callServer: sb.call_server?.name || '-',
                    call_server_id: sb.call_server_id,
                    country: sb.country || '',
                    province: sb.province || '',
                    address: sb.address || '',
                    contact_name: sb.contact_name || '',
                    contact_phone: sb.contact_phone || '',
                    description: sb.description || '',
                    active: sb.is_active,
                }));
                this.filteredRows = [...this.rows];
                this.loading = false;
            },
            error: (err) => {
                console.error('Failed to load sub branches:', err);
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

    loadCallServers() {
        const apiUrl = `${environment.apiUrl}/v1/call-servers`;
        this.http.get<any>(apiUrl).subscribe({
            next: (response) => {
                this.availableCallServers = response.data || [];
            },
            error: (err) => console.error('Failed to load call servers:', err)
        });
    }

    loadBranches(customerId: number) {
        this.organizationService.getBranches({ customer_id: customerId }).subscribe({
            next: (response) => {
                this.filteredBranches = response.data || [];
            },
            error: (err) => console.error('Failed to load branches:', err)
        });
    }

    onSearch() {
        this.loadData();
    }

    onCompanyChange() {
        if (this.formData.companyId) {
            this.loadBranches(this.formData.companyId);
        } else {
            this.filteredBranches = [];
        }
        this.formData.parentBranchId = null;
    }

    openModal(mode: 'create' | 'edit', item?: any) {
        this.modalMode = mode;
        this.contactExpanded = false;
        if (mode === 'edit' && item) {
            this.editingId = item.id;
            this.formData = {
                companyId: item.company_id,
                parentBranchId: item.branch_id,
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
                this.loadBranches(this.formData.companyId);
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
            parentBranchId: null,
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
        this.filteredBranches = [];
        this.editingId = null;
    }

    copyRecord(item: any) {
        this.modalMode = 'create';
        this.editingId = null;
        this.contactExpanded = false;
        this.formData = {
            companyId: item.company_id,
            parentBranchId: item.branch_id,
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
            this.loadBranches(this.formData.companyId);
        }
        this.showModal = true;
    }

    toggleContact() {
        this.contactExpanded = !this.contactExpanded;
    }

    saveRecord() {
        const payload: any = {
            customer_id: this.formData.companyId || undefined,
            branch_id: this.formData.parentBranchId || undefined,
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
            this.organizationService.updateSubBranch(this.editingId, payload).subscribe({
                next: () => {
                    Swal.fire('Success', 'Sub Branch updated successfully', 'success');
                    this.closeModal();
                    this.loadData();
                },
                error: (err) => {
                    console.error('Failed to update sub branch:', err);
                    Swal.fire('Error', 'Failed to update sub branch', 'error');
                }
            });
        } else {
            this.organizationService.createSubBranch(payload).subscribe({
                next: () => {
                    Swal.fire('Success', 'Sub Branch created successfully', 'success');
                    this.closeModal();
                    this.loadData();
                },
                error: (err) => {
                    console.error('Failed to create sub branch:', err);
                    Swal.fire('Error', 'Failed to create sub branch', 'error');
                }
            });
        }
    }

    deleteSubBranch(row: any) {
        Swal.fire({
            title: 'Delete Sub Branch?',
            text: 'Are you sure you want to delete this sub branch?',
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#d33',
            cancelButtonColor: '#3085d6',
            confirmButtonText: 'Yes, delete it!'
        }).then((result) => {
            if (result.isConfirmed) {
                this.organizationService.deleteSubBranch(row.id).subscribe({
                    next: () => {
                        Swal.fire('Deleted!', 'Sub Branch has been deleted.', 'success');
                        this.loadData();
                    },
                    error: (err) => {
                        console.error('Failed to delete sub branch:', err);
                        Swal.fire('Error', 'Failed to delete sub branch', 'error');
                    }
                });
            }
        });
    }
}
