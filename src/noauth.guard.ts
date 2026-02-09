import { Injectable } from '@angular/core';
import { Router } from '@angular/router';
import { AppService } from './app/service/app.service';

@Injectable({ providedIn: 'root' })
export class NoAuthGuard {
    constructor(
        private router: Router,
        private service: AppService,
    ) {}

    // async canActivate() {
    //     const bearerToken = this.service.get_localstorage('auth_token');

    //     if (bearerToken) {
    //         if (this.service.applicationSetting?.enable_landing_page) {
    //             this.router.navigate(['/']);
    //             return false;
    //         } else {
    //             this.router.navigate(['/dashboard']);
    //             return false;
    //         }
    //     }

    //     return true;
    // }
}
