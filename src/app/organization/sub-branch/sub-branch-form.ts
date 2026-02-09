import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, ActivatedRoute, RouterModule } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { OrganizationService, Company, Branch, SubBranch } from '../services/organization.service';
import { environment } from '../../../environments/environment';
import Swal from 'sweetalert2';

@Component({
    selector: 'app-sub-branch-form',
    templateUrl: './sub-branch-form.html',
    imports: [CommonModule, FormsModule, RouterModule],
})
export class SubBranchFormComponent implements OnInit {
    isEdit = false;
    subBranchId: number | null = null;
    contactExpanded = false;
    isLoading = false;

    companies: Company[] = [];
    branches: Branch[] = [];
    filteredBranches: Branch[] = [];
    availableCallServers: any[] = [];

    private http = inject(HttpClient);

    subBranch = {
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

    constructor(
        private router: Router,
        private route: ActivatedRoute,
        private organizationService: OrganizationService
    ) { }

    ngOnInit(): void {
        this.loadCompanies();
        this.loadCallServers();

        const id = this.route.snapshot.params['id'];
        const copyId = this.route.snapshot.queryParams['copy'];

        if (id) {
            this.isEdit = true;
            this.subBranchId = +id;
            this.loadSubBranch(this.subBranchId);
        } else if (copyId) {
            // Copy mode: load source record data but don't set isEdit
            this.loadSubBranchForCopy(+copyId);
        }
    }

    loadSubBranchForCopy(id: number) {
        this.organizationService.getSubBranch(id).subscribe({
            next: (response: any) => {
                const data = response.data || response;
                this.subBranch = {
                    companyId: data.customer_id,
                    parentBranchId: data.branch_id,
                    callServerId: data.call_server_id || null,
                    name: (data.name || '') + ' - Copy',
                    code: (data.code || '') + '-copy',
                    active: data.is_active ?? true,
                    country: data.country || 'Indonesia',
                    province: data.province || '',
                    city: data.city || '',
                    district: data.district || '',
                    address: data.address || '',
                    contactName: data.contact_name || '',
                    contactPhone: data.contact_phone || '',
                    description: data.description || '',
                };
                if (this.subBranch.companyId) {
                    this.loadBranches(this.subBranch.companyId);
                }
            },
            error: (err) => {
                console.error('Failed to load sub branch for copy:', err);
                Swal.fire('Error', 'Failed to load sub branch data', 'error');
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

    loadSubBranch(id: number) {
        this.organizationService.getSubBranch(id).subscribe({
            next: (response: any) => {
                const data = response.data || response;
                this.subBranch = {
                    companyId: data.customer_id,
                    parentBranchId: data.branch_id,
                    callServerId: data.call_server_id || null,
                    name: data.name || '',
                    code: data.code || '',
                    active: data.is_active ?? true,
                    country: data.country || 'Indonesia',
                    province: data.province || '',
                    city: data.city || '',
                    district: data.district || '',
                    address: data.address || '',
                    contactName: data.contact_name || '',
                    contactPhone: data.contact_phone || '',
                    description: data.description || '',
                };
                if (this.subBranch.companyId) {
                    this.loadBranches(this.subBranch.companyId);
                }
            },
            error: (err) => {
                console.error('Failed to load sub branch:', err);
                Swal.fire('Error', 'Failed to load sub branch data', 'error');
            }
        });
    }

    onCompanyChange() {
        if (this.subBranch.companyId) {
            this.loadBranches(this.subBranch.companyId);
        } else {
            this.filteredBranches = [];
        }
        this.subBranch.parentBranchId = null;
    }

    submit() {
        this.isLoading = true;
        const payload: any = {
            customer_id: this.subBranch.companyId || undefined,
            branch_id: this.subBranch.parentBranchId || undefined,
            call_server_id: this.subBranch.callServerId || undefined,
            name: this.subBranch.name,
            code: this.subBranch.code,
            is_active: this.subBranch.active,
            country: this.subBranch.country,
            province: this.subBranch.province,
            city: this.subBranch.city,
            district: this.subBranch.district,
            address: this.subBranch.address,
            contact_name: this.subBranch.contactName,
            contact_phone: this.subBranch.contactPhone,
            description: this.subBranch.description,
        };

        if (this.isEdit && this.subBranchId) {
            this.organizationService.updateSubBranch(this.subBranchId, payload).subscribe({
                next: () => {
                    this.isLoading = false;
                    Swal.fire('Success', 'Sub Branch updated successfully', 'success');
                    this.router.navigate(['/admin/organization/sub-branch']);
                },
                error: (err) => {
                    this.isLoading = false;
                    console.error('Failed to update sub branch:', err);
                    Swal.fire('Error', 'Failed to update sub branch', 'error');
                }
            });
        } else {
            this.organizationService.createSubBranch(payload).subscribe({
                next: () => {
                    this.isLoading = false;
                    Swal.fire('Success', 'Sub Branch created successfully', 'success');
                    this.router.navigate(['/admin/organization/sub-branch']);
                },
                error: (err) => {
                    this.isLoading = false;
                    console.error('Failed to create sub branch:', err);
                    Swal.fire('Error', 'Failed to create sub branch', 'error');
                }
            });
        }
    }

    submitAndCreateAnother() {
        this.isLoading = true;
        const payload: any = {
            customer_id: this.subBranch.companyId || undefined,
            branch_id: this.subBranch.parentBranchId || undefined,
            call_server_id: this.subBranch.callServerId || undefined,
            name: this.subBranch.name,
            code: this.subBranch.code,
            is_active: this.subBranch.active,
            country: this.subBranch.country,
            province: this.subBranch.province,
            city: this.subBranch.city,
            district: this.subBranch.district,
            address: this.subBranch.address,
            contact_name: this.subBranch.contactName,
            contact_phone: this.subBranch.contactPhone,
            description: this.subBranch.description,
        };

        this.organizationService.createSubBranch(payload).subscribe({
            next: () => {
                this.isLoading = false;
                Swal.fire('Success', 'Sub Branch created successfully', 'success');
                this.resetForm();
            },
            error: (err) => {
                this.isLoading = false;
                console.error('Failed to create sub branch:', err);
                Swal.fire('Error', 'Failed to create sub branch', 'error');
            }
        });
    }

    resetForm() {
        this.subBranch = {
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
    }

    cancel() {
        this.router.navigate(['/admin/organization/sub-branch']);
    }

    toggleContact() {
        this.contactExpanded = !this.contactExpanded;
    }
}

