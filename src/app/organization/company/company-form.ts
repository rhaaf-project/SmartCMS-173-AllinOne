import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, ActivatedRoute, RouterModule } from '@angular/router';
import { OrganizationService, Company } from '../services/organization.service';
import Swal from 'sweetalert2';

@Component({
    selector: 'app-company-form',
    templateUrl: './company-form.html',
    imports: [CommonModule, FormsModule, RouterModule],
})
export class CompanyFormComponent implements OnInit {
    isEdit = false;
    companyId: number | null = null;
    additionalInfoExpanded = false;
    isLoading = false;

    company = {
        name: '',
        code: '',
        active: true,
        contactPerson: '',
        email: '',
        phone: '',
        address: '',
    };

    constructor(
        private router: Router,
        private route: ActivatedRoute,
        private organizationService: OrganizationService
    ) { }

    ngOnInit(): void {
        const id = this.route.snapshot.params['id'];
        const copyId = this.route.snapshot.queryParams['copy'];

        if (id) {
            this.isEdit = true;
            this.companyId = +id;
            this.loadCompany(this.companyId);
        } else if (copyId) {
            this.loadCompanyForCopy(+copyId);
        }
    }

    loadCompanyForCopy(id: number) {
        this.organizationService.getCompany(id).subscribe({
            next: (response: any) => {
                const data = response.data || response;
                this.company = {
                    name: (data.name || '') + ' - Copy',
                    code: (data.code || '') + '-copy',
                    active: data.is_active ?? true,
                    contactPerson: data.contact_person || '',
                    email: data.email || '',
                    phone: data.phone || '',
                    address: data.address || '',
                };
            },
            error: (error) => {
                console.error('Failed to load company for copy:', error);
                Swal.fire('Error', 'Failed to load company data', 'error');
            },
        });
    }

    loadCompany(id: number) {
        this.organizationService.getCompany(id).subscribe({
            next: (response: any) => {
                const data = response.data || response;
                this.company = {
                    name: data.name || '',
                    code: data.code || '',
                    active: data.is_active ?? true,
                    contactPerson: data.contact_person || '',
                    email: data.email || '',
                    phone: data.phone || '',
                    address: data.address || '',
                };
            },
            error: (error) => {
                console.error('Failed to load company:', error);
                Swal.fire('Error', 'Failed to load company data', 'error');
            },
        });
    }

    submit() {
        this.isLoading = true;
        const payload: Company = {
            name: this.company.name,
            code: this.company.code,
            is_active: this.company.active,
            contact_person: this.company.contactPerson,
            email: this.company.email,
            phone: this.company.phone,
            address: this.company.address,
        };

        if (this.isEdit && this.companyId) {
            this.organizationService.updateCompany(this.companyId, payload).subscribe({
                next: () => {
                    this.isLoading = false;
                    Swal.fire('Success', 'Company updated successfully', 'success');
                    this.router.navigate(['/admin/organization/company']);
                },
                error: (error) => {
                    this.isLoading = false;
                    console.error('Failed to update company:', error);
                    Swal.fire('Error', 'Failed to update company', 'error');
                },
            });
        } else {
            this.organizationService.createCompany(payload).subscribe({
                next: () => {
                    this.isLoading = false;
                    Swal.fire('Success', 'Company created successfully', 'success');
                    this.router.navigate(['/admin/organization/company']);
                },
                error: (error) => {
                    this.isLoading = false;
                    console.error('Failed to create company:', error);
                    Swal.fire('Error', 'Failed to create company', 'error');
                },
            });
        }
    }

    submitAndCreateAnother() {
        this.isLoading = true;
        const payload: Company = {
            name: this.company.name,
            code: this.company.code,
            is_active: this.company.active,
            contact_person: this.company.contactPerson,
            email: this.company.email,
            phone: this.company.phone,
            address: this.company.address,
        };

        this.organizationService.createCompany(payload).subscribe({
            next: () => {
                this.isLoading = false;
                Swal.fire('Success', 'Company created successfully', 'success');
                this.company = {
                    name: '',
                    code: '',
                    active: true,
                    contactPerson: '',
                    email: '',
                    phone: '',
                    address: '',
                };
            },
            error: (error) => {
                this.isLoading = false;
                console.error('Failed to create company:', error);
                Swal.fire('Error', 'Failed to create company', 'error');
            },
        });
    }

    cancel() {
        this.router.navigate(['/admin/organization/company']);
    }

    toggleAdditionalInfo() {
        this.additionalInfoExpanded = !this.additionalInfoExpanded;
    }
}
