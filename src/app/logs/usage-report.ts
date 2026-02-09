import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../environments/environment';
import { IconDownloadComponent } from '../shared/icon/icon-download';
import { IconRefreshComponent } from '../shared/icon/icon-refresh';

interface UsageStatistic {
    id: number;
    date: string;
    branch_id: number;
    call_server_id: number;
    extension_number: string;
    line_inbound: number;
    line_outbound: number;
    ext_inbound: number;
    ext_outbound: number;
    vpw_inbound: number;
    vpw_outbound: number;
    cas_inbound: number;
    cas_outbound: number;
    sip_inbound: number;
    sip_outbound: number;
    total_time_inbound: number;
    total_time_outbound: number;
    total_time_inbound_formatted: string;
    total_time_outbound_formatted: string;
    branch_name: string;
    call_server_name: string;
    ip_address: string;
}

interface FilterOption {
    id: number;
    name: string;
    host?: string;
}

interface ApiResponse {
    success: boolean;
    data: UsageStatistic[];
    filters: {
        branches: FilterOption[];
        call_servers: FilterOption[];
    };
    meta: {
        date: string;
        total_records: number;
    };
}

@Component({
    selector: 'app-usage-report',
    standalone: true,
    imports: [CommonModule, FormsModule, IconDownloadComponent, IconRefreshComponent],
    templateUrl: './usage-report.html',
})
export class UsageReportComponent implements OnInit {
    data: UsageStatistic[] = [];
    branches: FilterOption[] = [];
    callServers: FilterOption[] = [];
    isLoading = false;

    // Filters
    selectedDate: string = new Date().toISOString().split('T')[0];
    selectedBranchId: number | null = null;
    selectedCallServerId: number | null = null;

    // Selected IP Address display
    selectedIpAddress: string = '';

    constructor(private http: HttpClient) { }

    ngOnInit() {
        this.loadData();
    }

    loadData() {
        this.isLoading = true;

        let url = `${environment.apiUrl}/v1/usage-report?date=${this.selectedDate}`;
        if (this.selectedBranchId) {
            url += `&branch_id=${this.selectedBranchId}`;
        }
        if (this.selectedCallServerId) {
            url += `&call_server_id=${this.selectedCallServerId}`;
        }

        this.http.get<ApiResponse>(url).subscribe({
            next: (response) => {
                this.data = response.data || [];
                this.branches = response.filters?.branches || [];
                this.callServers = response.filters?.call_servers || [];

                // Get IP address for display
                if (this.data.length > 0 && this.data[0].ip_address) {
                    this.selectedIpAddress = this.data[0].ip_address;
                } else if (this.selectedCallServerId) {
                    const selected = this.callServers.find(cs => cs.id === this.selectedCallServerId);
                    this.selectedIpAddress = selected?.host || '';
                } else {
                    this.selectedIpAddress = '';
                }

                this.isLoading = false;
            },
            error: (error) => {
                console.error('Failed to load usage report:', error);
                this.isLoading = false;
            },
        });
    }

    onFilterChange() {
        this.loadData();
    }

    onCallServerChange() {
        // Update IP address when call server changes
        if (this.selectedCallServerId) {
            const selected = this.callServers.find(cs => cs.id === this.selectedCallServerId);
            this.selectedIpAddress = selected?.host || '';
        } else {
            this.selectedIpAddress = '';
        }
        this.loadData();
    }

    downloadReport() {
        // Generate CSV
        const headers = ['No', 'Number', 'Line In', 'Line Out', 'Ext In', 'Ext Out', 'VPW In', 'VPW Out', 'CAS In', 'CAS Out', 'SIP In', 'SIP Out', 'Time In', 'Time Out'];
        const rows = this.data.map((item, index) => [
            index + 1,
            item.extension_number,
            item.line_inbound,
            item.line_outbound,
            item.ext_inbound,
            item.ext_outbound,
            item.vpw_inbound,
            item.vpw_outbound,
            item.cas_inbound,
            item.cas_outbound,
            item.sip_inbound,
            item.sip_outbound,
            item.total_time_inbound_formatted,
            item.total_time_outbound_formatted
        ]);

        const csv = [headers, ...rows].map(row => row.join(',')).join('\n');
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `usage_report_${this.selectedDate}.csv`;
        a.click();
        window.URL.revokeObjectURL(url);
    }

    getCategoryName(): string {
        if (this.selectedBranchId) {
            const branch = this.branches.find(b => b.id === this.selectedBranchId);
            return branch?.name || '';
        }
        return 'All Locations';
    }

    showValue(val: number): string {
        return val > 0 ? val.toString() : '-';
    }
}
