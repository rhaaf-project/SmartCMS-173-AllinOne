import { Component } from '@angular/core';
import { Router, RouterModule } from '@angular/router';
import { Store } from '@ngrx/store';
import { TranslateService } from '@ngx-translate/core';
import { toggleAnimation } from '../shared/animations';
import { AppService } from '../service/app.service';
import { IconCaretDownComponent } from '../shared/icon/icon-caret-down';
import { MenuModule } from 'headlessui-angular';
import { NgFor, NgClass, CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { IconMailComponent } from '../shared/icon/icon-mail';
import { IconLockDotsComponent } from '../shared/icon/icon-lock-dots';
import { IconInstagramComponent } from '../shared/icon/icon-instagram';
import { IconFacebookCircleComponent } from '../shared/icon/icon-facebook-circle';
import { IconTwitterComponent } from '../shared/icon/icon-twitter';
import { IconGoogleComponent } from '../shared/icon/icon-google';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../environments/environment';

@Component({
    templateUrl: './boxed-signin.html',
    animations: [toggleAnimation],
    imports: [
        NgFor,
        NgClass,
        CommonModule,
        MenuModule,
        RouterModule,
        FormsModule,
        IconCaretDownComponent,
        IconMailComponent,
        IconLockDotsComponent,
        IconInstagramComponent,
        IconFacebookCircleComponent,
        IconTwitterComponent,
        IconGoogleComponent,
    ],
})
export class BoxedSigninComponent {
    store: any;
    email: string = '';
    password: string = '';
    loading: boolean = false;
    errorMessage: string = '';
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

    handleLogin(event: any) {
        event.preventDefault();
        this.errorMessage = '';
        this.loading = true;

        // Validate inputs
        if (!this.email || !this.password) {
            this.errorMessage = 'Email and password are required';
            this.loading = false;
            return;
        }

        // Call login API
        this.http.post<any>(`${environment.apiUrl}/v1/login`, {
            email: this.email,
            password: this.password
        }).subscribe({
            next: (res) => {
                // Store user info for header profile and activity logs
                localStorage.setItem('auth_token', res.token);
                localStorage.setItem('userEmail', res.user.email);
                localStorage.setItem('userName', res.user.name);
                localStorage.setItem('userRole', res.user.role);
                localStorage.setItem('userId', res.user.id);
                localStorage.setItem('userProfileImage', res.user.profile_image || '');
                localStorage.setItem('isLoggedIn', 'true');

                this.loading = false;
                this.router.navigate(['/admin']);
            },
            error: (err) => {
                this.errorMessage = err.error?.error || 'Invalid email or password';
                this.loading = false;
            }
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
