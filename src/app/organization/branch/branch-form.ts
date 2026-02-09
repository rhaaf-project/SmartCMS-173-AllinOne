import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, ActivatedRoute, RouterModule } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { OrganizationService, Company, HeadOffice, Branch } from '../services/organization.service';
import { environment } from '../../../environments/environment';
import Swal from 'sweetalert2';

@Component({
    selector: 'app-branch-form',
    templateUrl: './branch-form.html',
    imports: [CommonModule, FormsModule, RouterModule],
})
export class BranchFormComponent implements OnInit {
    isEdit = false;
    branchId: number | null = null;
    contactExpanded = false;
    isLoading = false;

    companies: Company[] = [];
    headOffices: HeadOffice[] = [];
    callServers: any[] = [];
    filteredHeadOffices: HeadOffice[] = [];

    private http = inject(HttpClient);

    branch = {
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
            this.branchId = +id;
            this.loadBranch(this.branchId);
        } else if (copyId) {
            this.loadBranchForCopy(+copyId);
        }
    }

    loadBranchForCopy(id: number) {
        this.organizationService.getBranch(id).subscribe({
            next: (response: any) => {
                const data = response.data || response;
                this.branch = {
                    companyId: data.customer_id,
                    headOfficeId: data.head_office_id,
                    callServerId: data.call_server_id,
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
                if (this.branch.companyId) {
                    this.loadHeadOffices(this.branch.companyId);
                }
            },
            error: (err) => {
                console.error('Failed to load branch for copy:', err);
                Swal.fire('Error', 'Failed to load branch data', 'error');
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

    loadBranch(id: number) {
        this.organizationService.getBranch(id).subscribe({
            next: (response: any) => {
                const data = response.data || response;
                this.branch = {
                    companyId: data.customer_id,
                    headOfficeId: data.head_office_id,
                    callServerId: data.call_server_id,
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
                if (this.branch.companyId) {
                    this.loadHeadOffices(this.branch.companyId);
                }
            },
            error: (err) => {
                console.error('Failed to load branch:', err);
                Swal.fire('Error', 'Failed to load branch data', 'error');
            }
        });
    }

    onCompanyChange() {
        if (this.branch.companyId) {
            this.loadHeadOffices(this.branch.companyId);
        } else {
            this.filteredHeadOffices = [];
        }
        this.branch.headOfficeId = null;
    }

    submit() {
        this.isLoading = true;
        const payload: Branch = {
            customer_id: this.branch.companyId || undefined,
            head_office_id: this.branch.headOfficeId || undefined,
            call_server_id: this.branch.callServerId || undefined,
            name: this.branch.name,
            code: this.branch.code,
            is_active: this.branch.active,
            country: this.branch.country,
            province: this.branch.province,
            city: this.branch.city,
            district: this.branch.district,
            address: this.branch.address,
            contact_name: this.branch.contactName,
            contact_phone: this.branch.contactPhone,
            description: this.branch.description,
        };

        if (this.isEdit && this.branchId) {
            this.organizationService.updateBranch(this.branchId, payload).subscribe({
                next: () => {
                    this.isLoading = false;
                    Swal.fire('Success', 'Branch updated successfully', 'success');
                    this.router.navigate(['/admin/organization/branch']);
                },
                error: (err) => {
                    this.isLoading = false;
                    console.error('Failed to update branch:', err);
                    Swal.fire('Error', 'Failed to update branch', 'error');
                }
            });
        } else {
            this.organizationService.createBranch(payload).subscribe({
                next: () => {
                    this.isLoading = false;
                    Swal.fire('Success', 'Branch created successfully', 'success');
                    this.router.navigate(['/admin/organization/branch']);
                },
                error: (err) => {
                    this.isLoading = false;
                    console.error('Failed to create branch:', err);
                    Swal.fire('Error', 'Failed to create branch', 'error');
                }
            });
        }
    }

    submitAndCreateAnother() {
        this.isLoading = true;
        const payload: Branch = {
            customer_id: this.branch.companyId || undefined,
            head_office_id: this.branch.headOfficeId || undefined,
            call_server_id: this.branch.callServerId || undefined,
            name: this.branch.name,
            code: this.branch.code,
            is_active: this.branch.active,
            country: this.branch.country,
            province: this.branch.province,
            city: this.branch.city,
            district: this.branch.district,
            address: this.branch.address,
            contact_name: this.branch.contactName,
            contact_phone: this.branch.contactPhone,
            description: this.branch.description,
        };

        this.organizationService.createBranch(payload).subscribe({
            next: () => {
                this.isLoading = false;
                Swal.fire('Success', 'Branch created successfully', 'success');
                this.resetForm();
            },
            error: (err) => {
                this.isLoading = false;
                console.error('Failed to create branch:', err);
                Swal.fire('Error', 'Failed to create branch', 'error');
            }
        });
    }

    resetForm() {
        this.branch = {
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
    }

    cancel() {
        this.router.navigate(['/admin/organization/branch']);
    }

    toggleContact() {
        this.contactExpanded = !this.contactExpanded;
    }
}

