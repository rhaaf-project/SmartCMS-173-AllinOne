import { Component, inject } from '@angular/core';
import { Store } from '@ngrx/store';
import { toggleAnimation } from './shared/animations';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { environment } from '../environments/environment';

@Component({
    templateUrl: './index.html',
    animations: [toggleAnimation],
    imports: [CommonModule],
})
export class IndexComponent {
    store: any;
    stats: any = {};
    isLoading = true;
    private http = inject(HttpClient);

    constructor(public storeData: Store<any>) {
        this.initStore();
        this.loadStats();
    }

    async initStore() {
        this.storeData
            .select((d) => d.index)
            .subscribe((d) => {
                this.store = d;
            });
    }

    loadStats() {
        this.isLoading = true;
        const apiUrl = `${environment.apiUrl}/v1/stats`;

        this.http.get<any>(apiUrl).subscribe({
            next: (response) => {
                this.stats = response.data || {};
                this.isLoading = false;
            },
            error: (error) => {
                console.error('Failed to load stats:', error);
                // Set default values
                this.stats = {
                    // Row 1: Organization
                    ho: { active: 0, inactive: 0 },
                    branch: { active: 0, inactive: 0 },
                    subBranch: { active: 0, inactive: 0 },
                    callServer: { active: 0, inactive: 0 },

                    // Row 2: Line
                    line: { active: 0, inactive: 0 },
                    extension: { active: 0, inactive: 0 },
                    privateWire: { active: 0, inactive: 0 },
                    cas: { active: 0, inactive: 0 },
                    intercom: { active: 0, inactive: 0 },

                    // Row 3: Trunk/Routing
                    trunk: { active: 0, inactive: 0 },
                    inbound: { active: 0, inactive: 0 },
                    outbound: { active: 0, inactive: 0 },
                    conference: { active: 0, inactive: 0 },

                    // Row 4: SBC
                    sbc: { active: 0, inactive: 0 },
                    sbcConnection: { active: 0, inactive: 0 },
                    sbcRouting: { active: 0, inactive: 0 },
                    sipThirdParty: { active: 0, inactive: 0 },

                    // Row 5: Device
                    turret: { active: 0, inactive: 0 },
                    webDevice: { active: 0, inactive: 0 },
                    thirdPartyDevice: { active: 0, inactive: 0 },

                    // Row 6: Voice Gateway
                    analogFxoGateway: { active: 0, inactive: 0 },
                    analogFxsGateway: { active: 0, inactive: 0 },
                    e1Gateway: { active: 0, inactive: 0 },
                    e1CasGateway: { active: 0, inactive: 0 },

                    // Row 7: Recording & Alarm
                    recordingServer: { active: 0, inactive: 0 },
                    recordingChannel: { active: 0, inactive: 0 },
                    alarmNotification: { active: 0, inactive: 0 },
                };
                this.isLoading = false;
            },
        });
    }
}
