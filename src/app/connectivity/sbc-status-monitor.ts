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

interface LiveChannel {
    channel: string;
    source: string;
    destination: string;
    duration: string;
    state: string;
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
    liveChannels: LiveChannel[] = [];
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
        this.loadLiveChannels();
        this.setupAutoRefresh();
    }

    loadLiveChannels() {
        if (!this.selectedSbcId) return;

        this.isRefreshing = true;
        this.http.get<any>(`${environment.apiUrl}/v1/sbc-status/${this.selectedSbcId}`).subscribe({
            next: (response) => {
                this.liveChannels = response.data || [];
                this.lastRefreshed = new Date();
                this.isRefreshing = false;
            },
            error: (error) => {
                console.error('Failed to load live channels:', error);
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
                this.loadLiveChannels();
            }, 5000); // 5 seconds
        }
    }

    toggleAutoRefresh() {
        this.setupAutoRefresh();
    }

    manualRefresh() {
        this.loadLiveChannels();
    }
}
