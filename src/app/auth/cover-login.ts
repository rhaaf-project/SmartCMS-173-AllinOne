import { Component } from '@angular/core';
import { Router, RouterModule } from '@angular/router';
import { Store } from '@ngrx/store';
import { TranslateService } from '@ngx-translate/core';
import { toggleAnimation } from '../shared/animations';
import { AppService } from '../service/app.service';
import { MenuModule } from 'headlessui-angular';
import { IconCaretDownComponent } from '../shared/icon/icon-caret-down';
import { NgClass, NgFor, NgIf } from '@angular/common';
import { IconMailComponent } from '../shared/icon/icon-mail';
import { IconLockDotsComponent } from '../shared/icon/icon-lock-dots';
import { IconInstagramComponent } from '../shared/icon/icon-instagram';
import { IconFacebookComponent } from '../shared/icon/icon-facebook';
import { IconTwitterComponent } from '../shared/icon/icon-twitter';
import { IconGoogleComponent } from '../shared/icon/icon-google';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../environments/environment';

@Component({
    selector: 'app-cover-login',
    standalone: true,
    templateUrl: './cover-login.html',
    animations: [toggleAnimation],
    imports: [
        RouterModule,
        NgFor,
        NgClass,
        NgIf,
        MenuModule,
        FormsModule,
        IconCaretDownComponent,
        IconMailComponent,
        IconLockDotsComponent,
        IconInstagramComponent,
        IconFacebookComponent,
        IconTwitterComponent,
        IconGoogleComponent,
    ],
})
export class CoverLoginComponent {
    store: any;
    currYear: number = new Date().getFullYear();
    email: string = '';
    password: string = '';
    errorMessage: string = '';
    isLoading: boolean = false;
    showPassword: boolean = false;

    constructor(
        public translate: TranslateService,
        public storeData: Store<any>,
        public router: Router,
        private appSetting: AppService,
        private http: HttpClient,
    ) {
        this.initStore();
    }
    async initStore() {
        this.storeData
            .select((d) => d.index)
            .subscribe((d) => {
                this.store = d;
            });
    }

    login() {
        this.errorMessage = '';
        this.isLoading = true;

        // Validate inputs
        if (!this.email || !this.password) {
            this.errorMessage = 'Email and password are required';
            this.isLoading = false;
            return;
        }

        // Call login API
        this.http.post<any>(`${environment.apiUrl}/v1/login`, {
            email: this.email,
            password: this.password,
        }).subscribe({
            next: (response) => {
                if (response.success) {
                    // Store user info in localStorage
                    localStorage.setItem('userEmail', response.user.email);
                    localStorage.setItem('userName', response.user.name);
                    localStorage.setItem('isLoggedIn', 'true');
                    localStorage.setItem('token', response.token);

                    this.isLoading = false;
                    this.router.navigate(['/']);
                }
            },
            error: (error) => {
                this.errorMessage = error.error?.error || 'Invalid email or password';
                this.isLoading = false;
            },
        });
    }

    changeLanguage(item: any) {
        this.translate.use(item.code);
        this.appSetting.toggleLanguage(item);
        if (this.store.locale?.toLowerCase() === 'ae') {
            this.storeData.dispatch({ type: 'toggleRTL', payload: 'rtl' });
        } else {
            this.storeData.dispatch({ type: 'toggleRTL', payload: 'ltr' });
        }
        window.location.reload();
    }
}
