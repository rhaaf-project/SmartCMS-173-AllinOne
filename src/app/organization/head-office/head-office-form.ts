import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, ActivatedRoute, RouterModule } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { OrganizationService, Company, HeadOffice } from '../services/organization.service';
import { environment } from '../../../environments/environment';
import Swal from 'sweetalert2';

interface CallServerSlot {
    callServerId: number | null;
    isEnabled: boolean;
}

@Component({
    selector: 'app-head-office-form',
    templateUrl: './head-office-form.html',
    imports: [CommonModule, FormsModule, RouterModule],
})
export class HeadOfficeFormComponent implements OnInit {
    isEdit = false;
    headOfficeId: number | null = null;
    contactExpanded = false;
    isLoading = false;

    companies: Company[] = [];
    availableCallServers: any[] = [];
    callServerSlots: CallServerSlot[] = [];

    private http = inject(HttpClient);

    siteTypes = [
        { value: 'basic', label: 'Basic (Single Site)' },
        { value: 'ha', label: 'HA (High Availability)' },
        { value: 'fo', label: 'FO (Failover/Redundancy)' },
    ];

    headOffice = {
        companyId: null as number | null,
        name: '',
        code: '',
        active: true,
        type: 'ha',
        country: 'Indonesia',
        province: '',
        city: '',
        district: '',
        address: '',
        contactName: '',
        contactPhone: '',
        description: '',
        bcpDrcServerId: null as number | null,
        bcpDrcEnabled: false,
    };

    constructor(
        private router: Router,
        private route: ActivatedRoute,
        private organizationService: OrganizationService
    ) { }

    ngOnInit(): void {
        this.loadCompanies();
        this.loadCallServers();
        this.initCallServerSlots();

        const id = this.route.snapshot.params['id'];
        const copyId = this.route.snapshot.queryParams['copy'];

        if (id) {
            this.isEdit = true;
            this.headOfficeId = +id;
            this.loadHeadOffice(this.headOfficeId);
        } else if (copyId) {
            this.loadHeadOfficeForCopy(+copyId);
        }
    }

    loadHeadOfficeForCopy(id: number) {
        this.organizationService.getHeadOffice(id).subscribe({
            next: (response: any) => {
                const data = response.data || response;
                this.headOffice = {
                    companyId: data.customer_id,
                    name: (data.name || '') + ' - Copy',
                    code: (data.code || '') + '-copy',
                    active: data.is_active ?? true,
                    type: data.type || 'ha',
                    country: data.country || 'Indonesia',
                    province: data.province || '',
                    city: data.city || '',
                    district: data.district || '',
                    address: data.address || '',
                    contactName: data.contact_name || '',
                    contactPhone: data.contact_phone || '',
                    description: data.description || '',
                    bcpDrcServerId: data.bcp_drc_server_id || null,
                    bcpDrcEnabled: data.bcp_drc_enabled ?? false,
                };
                if (data.call_servers_json) {
                    try {
                        const parsed = JSON.parse(data.call_servers_json);
                        this.callServerSlots = parsed.map((s: any) => ({
                            callServerId: s.call_server_id,
                            isEnabled: s.is_enabled ?? true
                        }));
                    } catch (e) {
                        this.initCallServerSlots();
                    }
                } else {
                    this.initCallServerSlots();
                }
            },
            error: (err) => {
                console.error('Failed to load head office for copy:', err);
                Swal.fire('Error', 'Failed to load head office data', 'error');
            }
        });
    }

    loadCompanies() {
        this.organizationService.getCompanies().subscribe({
            next: (response) => {
                this.companies = response.data || [];
            },
            error: (err) => {
                console.error('Failed to load companies:', err);
            }
        });
    }

    loadCallServers() {
        const apiUrl = `${environment.apiUrl}/v1/call-servers`;
        this.http.get<any>(apiUrl).subscribe({
            next: (response) => {
                this.availableCallServers = response.data || [];
            },
            error: (err) => {
                console.error('Failed to load call servers:', err);
            }
        });
    }

    initCallServerSlots() {
        const count = this.getServerCount(this.headOffice.type);
        this.callServerSlots = Array(count).fill(null).map(() => ({
            callServerId: null,
            isEnabled: true
        }));
    }

    getServerCount(type: string): number {
        switch (type) {
            case 'ha': return 3;
            case 'fo': return 2;
            case 'basic': return 1;
            default: return 0;
        }
    }

    onTypeChange() {
        this.initCallServerSlots();
    }

    getTypeDescription(): string {
        switch (this.headOffice.type) {
            case 'ha': return 'High Availability requires 3 Call Servers';
            case 'fo': return 'Failover/Redundancy requires 2 Call Servers';
            case 'basic': return 'Basic site uses 1 Call Server';
            default: return 'Select Call Servers for this site';
        }
    }

    isServerSelected(serverId: number, currentIndex: number): boolean {
        return this.callServerSlots.some((slot, i) =>
            i !== currentIndex && slot.callServerId === serverId
        );
    }

    loadHeadOffice(id: number) {
        this.organizationService.getHeadOffice(id).subscribe({
            next: (response: any) => {
                const data = response.data || response;
                this.headOffice = {
                    companyId: data.customer_id,
                    name: data.name || '',
                    code: data.code || '',
                    active: data.is_active ?? true,
                    type: data.type || 'ha',
                    country: data.country || 'Indonesia',
                    province: data.province || '',
                    city: data.city || '',
                    district: data.district || '',
                    address: data.address || '',
                    contactName: data.contact_name || '',
                    contactPhone: data.contact_phone || '',
                    description: data.description || '',
                    bcpDrcServerId: data.bcp_drc_server_id || null,
                    bcpDrcEnabled: data.bcp_drc_enabled ?? false,
                };
                // Load call servers from JSON
                if (data.call_servers_json) {
                    try {
                        const parsed = JSON.parse(data.call_servers_json);
                        this.callServerSlots = parsed.map((s: any) => ({
                            callServerId: s.call_server_id,
                            isEnabled: s.is_enabled ?? true
                        }));
                    } catch (e) {
                        this.initCallServerSlots();
                    }
                } else {
                    this.initCallServerSlots();
                }
            },
            error: (err) => {
                console.error('Failed to load head office:', err);
                Swal.fire('Error', 'Failed to load head office data', 'error');
            }
        });
    }

    submit() {
        this.isLoading = true;

        // Build call_servers_json from slots
        const callServersJson = JSON.stringify(
            this.callServerSlots.map(slot => ({
                call_server_id: slot.callServerId,
                is_enabled: slot.isEnabled
            }))
        );

        const payload: any = {
            customer_id: this.headOffice.companyId!,
            name: this.headOffice.name,
            code: this.headOffice.code,
            is_active: this.headOffice.active,
            type: this.headOffice.type,
            country: this.headOffice.country,
            province: this.headOffice.province,
            city: this.headOffice.city,
            district: this.headOffice.district,
            address: this.headOffice.address,
            contact_name: this.headOffice.contactName,
            contact_phone: this.headOffice.contactPhone,
            description: this.headOffice.description,
            bcp_drc_server_id: this.headOffice.bcpDrcServerId,
            bcp_drc_enabled: this.headOffice.bcpDrcEnabled ? 1 : 0,
            call_servers_json: callServersJson,
        };

        if (this.isEdit && this.headOfficeId) {
            this.organizationService.updateHeadOffice(this.headOfficeId, payload).subscribe({
                next: () => {
                    this.isLoading = false;
                    Swal.fire('Success', 'Head Office updated successfully', 'success');
                    this.router.navigate(['/admin/organization/head-office']);
                },
                error: (err) => {
                    this.isLoading = false;
                    console.error('Failed to update head office:', err);
                    Swal.fire('Error', 'Failed to update head office', 'error');
                }
            });
        } else {
            this.organizationService.createHeadOffice(payload).subscribe({
                next: () => {
                    this.isLoading = false;
                    Swal.fire('Success', 'Head Office created successfully', 'success');
                    this.router.navigate(['/admin/organization/head-office']);
                },
                error: (err) => {
                    this.isLoading = false;
                    console.error('Failed to create head office:', err);
                    Swal.fire('Error', 'Failed to create head office', 'error');
                }
            });
        }
    }

    submitAndCreateAnother() {
        this.isLoading = true;

        const callServersJson = JSON.stringify(
            this.callServerSlots.map(slot => ({
                call_server_id: slot.callServerId,
                is_enabled: slot.isEnabled
            }))
        );

        const payload: any = {
            customer_id: this.headOffice.companyId!,
            name: this.headOffice.name,
            code: this.headOffice.code,
            is_active: this.headOffice.active,
            type: this.headOffice.type,
            country: this.headOffice.country,
            province: this.headOffice.province,
            city: this.headOffice.city,
            district: this.headOffice.district,
            address: this.headOffice.address,
            contact_name: this.headOffice.contactName,
            contact_phone: this.headOffice.contactPhone,
            description: this.headOffice.description,
            bcp_drc_server_id: this.headOffice.bcpDrcServerId,
            bcp_drc_enabled: this.headOffice.bcpDrcEnabled ? 1 : 0,
            call_servers_json: callServersJson,
        };

        this.organizationService.createHeadOffice(payload).subscribe({
            next: () => {
                this.isLoading = false;
                Swal.fire('Success', 'Head Office created successfully', 'success');
                this.resetForm();
            },
            error: (err) => {
                this.isLoading = false;
                console.error('Failed to create head office:', err);
                Swal.fire('Error', 'Failed to create head office', 'error');
            }
        });
    }

    resetForm() {
        this.headOffice = {
            companyId: null,
            name: '',
            code: '',
            active: true,
            type: 'ha',
            country: 'Indonesia',
            province: '',
            city: '',
            district: '',
            address: '',
            contactName: '',
            contactPhone: '',
            description: '',
            bcpDrcServerId: null,
            bcpDrcEnabled: false,
        };
        this.initCallServerSlots();
    }

    cancel() {
        this.router.navigate(['/admin/organization/head-office']);
    }

    toggleContact() {
        this.contactExpanded = !this.contactExpanded;
    }
}

