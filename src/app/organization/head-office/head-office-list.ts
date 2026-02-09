import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { DataTableModule } from '@bhplugin/ng-datatable';
import { OrganizationService, Company, HeadOffice } from '../services/organization.service';
import { environment } from '../../../environments/environment';
import { IconCircleCheckComponent } from '../../shared/icon/icon-circle-check';
import Swal from 'sweetalert2';

interface CallServerSlot {
    callServerId: number | null;
    isEnabled: boolean;
}

@Component({
    selector: 'app-head-office-list',
    templateUrl: './head-office-list.html',
    imports: [CommonModule, FormsModule, RouterModule, DataTableModule, IconCircleCheckComponent],
})
export class HeadOfficeListComponent implements OnInit {
    loading = false;
    search = '';
    showModal = false;
    modalMode: 'create' | 'edit' = 'create';
    editingId: number | null = null;
    contactExpanded = false;

    companies: Company[] = [];
    availableCallServers: any[] = [];
    callServerSlots: CallServerSlot[] = [];

    private http = inject(HttpClient);

    siteTypes = [
        { value: 'basic', label: 'Basic (Single Site)' },
        { value: 'ha', label: 'HA (High Availability)' },
        { value: 'fo', label: 'FO (Failover/Redundancy)' },
    ];

    formData = {
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

    cols = [
        { field: 'company', title: 'Company' },
        { field: 'name', title: 'Name' },
        { field: 'type', title: 'Type', headerClass: 'justify-center', cellClass: 'justify-center' },
        { field: 'city', title: 'City' },
        { field: 'servers', title: 'Servers', headerClass: 'justify-center', cellClass: 'justify-center' },
        { field: 'branches', title: 'Branches', headerClass: 'justify-center', cellClass: 'justify-center' },
        { field: 'active', title: 'Active', sort: false, headerClass: 'justify-center', cellClass: 'justify-center' },
        { field: 'actions', title: '', sort: false, headerClass: '!text-center', cellClass: '!text-center' },
    ];

    rows: any[] = [];
    filteredRows: any[] = [];

    typeLabels: { [key: string]: string } = {
        basic: 'Basic',
        ha: 'HA',
        fo: 'FO',
    };

    constructor(private organizationService: OrganizationService) { }

    ngOnInit(): void {
        this.loadData();
        this.loadCompanies();
        this.loadCallServers();
    }

    loadData() {
        this.loading = true;
        this.organizationService.getHeadOffices({ search: this.search }).subscribe({
            next: (response) => {
                this.rows = (response.data || []).map((ho: any) => ({
                    id: ho.id,
                    company: ho.customer?.name || '-',
                    company_id: ho.customer_id,
                    name: ho.name,
                    code: ho.code || '',
                    type: ho.type || 'basic',
                    city: ho.city || '-',
                    country: ho.country || '',
                    province: ho.province || '',
                    district: ho.district || '',
                    address: ho.address || '',
                    contact_name: ho.contact_name || '',
                    contact_phone: ho.contact_phone || '',
                    description: ho.description || '',
                    bcp_drc_server_id: ho.bcp_drc_server_id,
                    bcp_drc_enabled: ho.bcp_drc_enabled,
                    call_servers_json: ho.call_servers_json,
                    servers: ho.call_servers_count || 0,
                    branches: ho.branches_count || 0,
                    active: ho.is_active,
                }));
                this.filteredRows = [...this.rows];
                this.loading = false;
            },
            error: (err) => {
                console.error('Failed to load head offices:', err);
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

    onSearch() {
        this.loadData();
    }

    getTypeLabel(type: string): string {
        return this.typeLabels[type] || type;
    }

    getTypeClass(type: string): string {
        switch (type) {
            case 'ha':
                return 'badge bg-success';
            case 'fo':
                return 'badge bg-warning';
            default:
                return 'badge bg-dark';
        }
    }

    openModal(mode: 'create' | 'edit', item?: any) {
        this.modalMode = mode;
        this.contactExpanded = false;
        if (mode === 'edit' && item) {
            this.editingId = item.id;
            this.formData = {
                companyId: item.company_id,
                name: item.name || '',
                code: item.code || '',
                active: item.active ?? true,
                type: item.type || 'ha',
                country: item.country || 'Indonesia',
                province: item.province || '',
                city: item.city === '-' ? '' : item.city,
                district: item.district || '',
                address: item.address || '',
                contactName: item.contact_name || '',
                contactPhone: item.contact_phone || '',
                description: item.description || '',
                bcpDrcServerId: item.bcp_drc_server_id || null,
                bcpDrcEnabled: item.bcp_drc_enabled ?? false,
            };
            // Load call servers from JSON
            if (item.call_servers_json) {
                try {
                    const parsed = JSON.parse(item.call_servers_json);
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
        this.editingId = null;
    }

    copyRecord(item: any) {
        this.modalMode = 'create';
        this.editingId = null;
        this.contactExpanded = false;
        this.formData = {
            companyId: item.company_id,
            name: (item.name || '') + ' - Copy',
            code: (item.code || '') + '-copy',
            active: item.active ?? true,
            type: item.type || 'ha',
            country: item.country || 'Indonesia',
            province: item.province || '',
            city: item.city === '-' ? '' : item.city,
            district: item.district || '',
            address: item.address || '',
            contactName: item.contact_name || '',
            contactPhone: item.contact_phone || '',
            description: item.description || '',
            bcpDrcServerId: item.bcp_drc_server_id || null,
            bcpDrcEnabled: item.bcp_drc_enabled ?? false,
        };
        if (item.call_servers_json) {
            try {
                const parsed = JSON.parse(item.call_servers_json);
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
        this.showModal = true;
    }

    initCallServerSlots() {
        const count = this.getServerCount(this.formData.type);
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
        switch (this.formData.type) {
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

    toggleContact() {
        this.contactExpanded = !this.contactExpanded;
    }

    saveRecord() {
        const callServersJson = JSON.stringify(
            this.callServerSlots.map(slot => ({
                call_server_id: slot.callServerId,
                is_enabled: slot.isEnabled
            }))
        );

        const payload: any = {
            customer_id: this.formData.companyId!,
            name: this.formData.name,
            code: this.formData.code,
            is_active: this.formData.active,
            type: this.formData.type,
            country: this.formData.country,
            province: this.formData.province,
            city: this.formData.city,
            district: this.formData.district,
            address: this.formData.address,
            contact_name: this.formData.contactName,
            contact_phone: this.formData.contactPhone,
            description: this.formData.description,
            bcp_drc_server_id: this.formData.bcpDrcServerId,
            bcp_drc_enabled: this.formData.bcpDrcEnabled ? 1 : 0,
            call_servers_json: callServersJson,
        };

        if (this.modalMode === 'edit' && this.editingId) {
            this.organizationService.updateHeadOffice(this.editingId, payload).subscribe({
                next: () => {
                    Swal.fire('Success', 'Head Office updated successfully', 'success');
                    this.closeModal();
                    this.loadData();
                },
                error: (err) => {
                    console.error('Failed to update head office:', err);
                    Swal.fire('Error', 'Failed to update head office', 'error');
                }
            });
        } else {
            this.organizationService.createHeadOffice(payload).subscribe({
                next: () => {
                    Swal.fire('Success', 'Head Office created successfully', 'success');
                    this.closeModal();
                    this.loadData();
                },
                error: (err) => {
                    console.error('Failed to create head office:', err);
                    Swal.fire('Error', 'Failed to create head office', 'error');
                }
            });
        }
    }

    deleteHeadOffice(row: any) {
        Swal.fire({
            title: 'Delete Head Office?',
            text: 'Are you sure you want to delete this head office?',
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#d33',
            cancelButtonColor: '#3085d6',
            confirmButtonText: 'Yes, delete it!'
        }).then((result) => {
            if (result.isConfirmed) {
                this.organizationService.deleteHeadOffice(row.id).subscribe({
                    next: () => {
                        Swal.fire('Deleted!', 'Head Office has been deleted.', 'success');
                        this.loadData();
                    },
                    error: (err) => {
                        console.error('Failed to delete head office:', err);
                        Swal.fire('Error', 'Failed to delete head office', 'error');
                    }
                });
            }
        });
    }
}
