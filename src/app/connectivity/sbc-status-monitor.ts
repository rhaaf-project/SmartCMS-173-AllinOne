import { Component, inject, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { Store } from '@ngrx/store';
import { environment } from '../../environments/environment';
import { IconCircleCheckComponent } from '../shared/icon/icon-circle-check';
import { IconXCircleComponent } from '../shared/icon/icon-x-circle';
import { IconRefreshComponent } from '../shared/icon/icon-refresh';

interface SBCNode {
    id: number;
    name: string;
    host: string;
    port: number;
    is_active: boolean;
}

interface ConnectionStatus {
    id: number;
    sbc_id: number;
    peer_name: string;
    peer_type: 'ITSP' | 'IP_GROUP' | 'TRUNK_GROUP' | 'SIP_PEER' | 'GATEWAY';
    remote_address: string;
    local_user: string | null;
    registration_status: 'REGISTERED' | 'NOT_REGISTERED' | 'REGISTERING' | 'FAILED';
    connection_status: 'OK' | 'LAGGED' | 'UNREACHABLE' | 'UNKNOWN';
    latency_ms: number | null;
    active_calls: number;
    max_calls: number | null;
    last_activity: string;
}

@Component({
    templateUrl: './sbc-status-monitor.html',
    imports: [CommonModule, FormsModule, IconCircleCheckComponent, IconXCircleComponent, IconRefreshComponent],
})
export class SBCStatusMonitorComponent implements OnInit, OnDestroy {
    store: any;
    sbcNodes: SBCNode[] = [];
    selectedSbcId: number | null = null;
    selectedSbc: SBCNode | null = null;
    connectionStatuses: ConnectionStatus[] = [];
    isLoading = false;
    isRefreshing = false;
    lastRefreshed: Date | null = null;
    autoRefreshInterval: any = null;
    autoRefreshEnabled = true;

    private http = inject(HttpClient);

    constructor(public storeData: Store<any>) {
        this.initStore();
    }

    async initStore() {
        this.storeData.select((d) => d.index).subscribe((d) => { this.store = d; });
    }

    ngOnInit() {
        this.loadSbcNodes();
    }

    ngOnDestroy() {
        if (this.autoRefreshInterval) {
            clearInterval(this.autoRefreshInterval);
        }
    }

    loadSbcNodes() {
        this.isLoading = true;
        this.http.get<any>(`${environment.apiUrl}/v1/call-servers?type=sbc`).subscribe({
            next: (response) => {
                this.sbcNodes = response.data || [];
                this.isLoading = false;
                if (this.sbcNodes.length > 0 && !this.selectedSbcId) {
                    this.selectedSbcId = this.sbcNodes[0].id;
                    this.onSbcChange();
                }
            },
            error: (error) => {
                console.error('Failed to load SBC nodes:', error);
                this.isLoading = false;
            },
        });
    }

    onSbcChange() {
        this.selectedSbc = this.sbcNodes.find(s => s.id === this.selectedSbcId) || null;
        this.loadConnectionStatuses();
        this.setupAutoRefresh();
    }

    loadConnectionStatuses() {
        if (!this.selectedSbcId) return;

        this.isRefreshing = true;
        this.http.get<any>(`${environment.apiUrl}/v1/sbc-status/${this.selectedSbcId}`).subscribe({
            next: (response) => {
                this.connectionStatuses = response.data || [];
                this.lastRefreshed = new Date();
                this.isRefreshing = false;
            },
            error: (error) => {
                console.error('Failed to load connection statuses:', error);
                this.isRefreshing = false;
            },
        });
    }

    setupAutoRefresh() {
        if (this.autoRefreshInterval) {
            clearInterval(this.autoRefreshInterval);
        }
        if (this.autoRefreshEnabled) {
            this.autoRefreshInterval = setInterval(() => {
                this.loadConnectionStatuses();
            }, 30000);
        }
    }

    toggleAutoRefresh() {
        this.autoRefreshEnabled = !this.autoRefreshEnabled;
        this.setupAutoRefresh();
    }

    manualRefresh() {
        this.loadConnectionStatuses();
    }

    getConnectionStatusClass(status: string): string {
        switch (status) {
            case 'OK': return 'bg-success/20 text-success';
            case 'LAGGED': return 'bg-warning/20 text-warning';
            case 'UNREACHABLE': return 'bg-danger/20 text-danger';
            default: return 'bg-gray-500/20 text-gray-500';
        }
    }

    getRegistrationStatusClass(status: string): string {
        switch (status) {
            case 'REGISTERED': return 'bg-success/20 text-success';
            case 'REGISTERING': return 'bg-info/20 text-info';
            case 'NOT_REGISTERED': return 'bg-gray-500/20 text-gray-500';
            case 'FAILED': return 'bg-danger/20 text-danger';
            default: return 'bg-gray-500/20 text-gray-500';
        }
    }

    getPeerTypeLabel(type: string): string {
        switch (type) {
            case 'ITSP': return 'ITSP Trunk';
            case 'IP_GROUP': return 'IP Group';
            case 'TRUNK_GROUP': return 'Trunk Group';
            case 'SIP_PEER': return 'SIP Peer';
            case 'GATEWAY': return 'Gateway';
            default: return type;
        }
    }

    getPeerTypeBadgeClass(type: string): string {
        switch (type) {
            case 'ITSP': return 'bg-primary/20 text-primary';
            case 'IP_GROUP': return 'bg-info/20 text-info';
            case 'TRUNK_GROUP': return 'bg-secondary/20 text-secondary';
            case 'SIP_PEER': return 'bg-warning/20 text-warning';
            case 'GATEWAY': return 'bg-dark/20 text-dark';
            default: return 'bg-gray-500/20 text-gray-500';
        }
    }

    formatLastActivity(dateStr: string): string {
        if (!dateStr) return '-';
        const date = new Date(dateStr);
        const now = new Date();
        const diffSeconds = Math.floor((now.getTime() - date.getTime()) / 1000);

        if (diffSeconds < 60) return `${diffSeconds}s ago`;
        if (diffSeconds < 3600) return `${Math.floor(diffSeconds / 60)}m ago`;
        if (diffSeconds < 86400) return `${Math.floor(diffSeconds / 3600)}h ago`;
        return `${Math.floor(diffSeconds / 86400)}d ago`;
    }

    get okCount(): number {
        return this.connectionStatuses.filter(c => c.connection_status === 'OK').length;
    }

    get laggedCount(): number {
        return this.connectionStatuses.filter(c => c.connection_status === 'LAGGED').length;
    }

    get unreachableCount(): number {
        return this.connectionStatuses.filter(c => c.connection_status === 'UNREACHABLE').length;
    }

    get totalActiveCalls(): number {
        return this.connectionStatuses.reduce((sum, c) => sum + (c.active_calls || 0), 0);
    }

    get registeredCount(): number {
        return this.connectionStatuses.filter(c => c.registration_status === 'REGISTERED').length;
    }

    // Export to CSV
    exportCSV() {
        if (this.connectionStatuses.length === 0) return;

        const headers = ['Peer Name', 'Type', 'Remote Address', 'Local User', 'Registration', 'Connection', 'Latency (ms)', 'Active Calls', 'Max Calls', 'Last Activity'];
        const rows = this.connectionStatuses.map(c => [
            c.peer_name,
            this.getPeerTypeLabel(c.peer_type),
            c.remote_address,
            c.local_user || '-',
            c.registration_status,
            c.connection_status,
            c.latency_ms !== null ? c.latency_ms.toString() : '-',
            c.active_calls.toString(),
            c.max_calls !== null ? c.max_calls.toString() : '-',
            c.last_activity || '-'
        ]);

        const csvContent = [headers, ...rows].map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        const url = URL.createObjectURL(blob);
        const timestamp = new Date().toISOString().slice(0, 10);
        link.setAttribute('href', url);
        link.setAttribute('download', `SBC_Status_${this.selectedSbc?.name || 'Report'}_${timestamp}.csv`);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }

    // Print Report
    printReport() {
        const printContent = document.getElementById('sbc-status-table');
        if (!printContent) return;

        const sbcInfo = this.selectedSbc ? `
            <div style="margin-bottom: 20px;">
                <p><strong>SBC Name:</strong> ${this.selectedSbc.name}</p>
                <p><strong>IP Address:</strong> ${this.selectedSbc.host}</p>
                <p><strong>Port:</strong> ${this.selectedSbc.port}</p>
                <p><strong>Generated:</strong> ${new Date().toLocaleString()}</p>
            </div>
        ` : '';

        const printWindow = window.open('', '_blank');
        if (printWindow) {
            printWindow.document.write(`
                <html>
                <head>
                    <title>SBC Status Report - ${this.selectedSbc?.name || 'Report'}</title>
                    <style>
                        body { font-family: Arial, sans-serif; padding: 20px; }
                        h1 { color: #333; border-bottom: 2px solid #333; padding-bottom: 10px; }
                        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                        th { background-color: #f5f5f5; font-weight: bold; }
                        .status-ok { color: green; }
                        .status-lagged { color: orange; }
                        .status-unreachable { color: red; }
                        @media print { body { -webkit-print-color-adjust: exact; print-color-adjust: exact; } }
                    </style>
                </head>
                <body>
                    <h1>SBC Connection Status Report</h1>
                    ${sbcInfo}
                    ${printContent.outerHTML}
                </body>
                </html>
            `);
            printWindow.document.close();
            printWindow.print();
        }
    }
}
