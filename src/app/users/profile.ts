import { Component, OnInit, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { environment } from '../../environments/environment';
import { toggleAnimation } from '../shared/animations';
import { MenuModule } from 'headlessui-angular';

// Icons
import { IconPencilPaperComponent } from '../shared/icon/icon-pencil-paper';
import { IconCoffeeComponent } from '../shared/icon/icon-coffee';
import { IconCalendarComponent } from '../shared/icon/icon-calendar';
import { IconMapPinComponent } from '../shared/icon/icon-map-pin';
import { IconMailComponent } from '../shared/icon/icon-mail';
import { IconPhoneComponent } from '../shared/icon/icon-phone';
import { IconTwitterComponent } from '../shared/icon/icon-twitter';
import { IconDribbbleComponent } from '../shared/icon/icon-dribbble';
import { IconGithubComponent } from '../shared/icon/icon-github';
import { IconShoppingBagComponent } from '../shared/icon/icon-shopping-bag';
import { IconTagComponent } from '../shared/icon/icon-tag';
import { IconCreditCardComponent } from '../shared/icon/icon-credit-card';
import { IconClockComponent } from '../shared/icon/icon-clock';
import { IconHorizontalDotsComponent } from '../shared/icon/icon-horizontal-dots';

@Component({
    templateUrl: './profile.html',
    animations: [toggleAnimation],
    imports: [
        CommonModule,
        RouterModule,
        MenuModule,
        IconPencilPaperComponent,
        IconCoffeeComponent,
        IconCalendarComponent,
        IconMapPinComponent,
        IconMailComponent,
        IconPhoneComponent,
        IconTwitterComponent,
        IconDribbbleComponent,
        IconGithubComponent,
        IconShoppingBagComponent,
        IconTagComponent,
        IconCreditCardComponent,
        IconClockComponent,
        IconHorizontalDotsComponent,
    ],
})
export class ProfileComponent implements OnInit {
    user: any = {};
    logs: any[] = [];
    isLoadingLogs = false;
    imageBaseUrl = environment.imageBaseUrl;
    private http = inject(HttpClient);

    constructor() { }

    ngOnInit() {
        // Load from localStorage first as fallback
        this.user = {
            name: localStorage.getItem('userName') || 'User',
            email: localStorage.getItem('userEmail') || '',
            role: localStorage.getItem('userRole') || 'Viewer',
            profile_image: localStorage.getItem('userProfileImage') || ''
        };

        // Then fetch fresh data from API
        const userId = localStorage.getItem('userId');
        if (userId) {
            this.http.get<any>(`${environment.apiUrl}/me?user_id=${userId}`).subscribe({
                next: (res) => {
                    if (res.success && res.data) {
                        this.user = res.data;
                        // Update localStorage with fresh data
                        localStorage.setItem('userName', res.data.name || '');
                        localStorage.setItem('userEmail', res.data.email || '');
                        localStorage.setItem('userRole', res.data.role || '');
                        localStorage.setItem('userProfileImage', res.data.profile_image || '');
                    }
                },
                error: () => { /* Keep localStorage data on error */ }
            });
        }
        this.loadLogs();
    }

    loadLogs() {
        const userId = localStorage.getItem('userId');
        if (!userId) return;

        this.isLoadingLogs = true;
        this.http.get<any>(`${environment.apiUrl}/v1/activity_logs?user_id=${userId}&per_page=10`).subscribe({
            next: (res) => {
                this.logs = res.data || [];
                this.isLoadingLogs = false;
            },
            error: () => {
                this.isLoadingLogs = false;
            }
        });
    }
}
