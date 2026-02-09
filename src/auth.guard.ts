// import { AuthService } from 'src/app/shared/auth.service';
import { Injectable } from '@angular/core';
import { Router, RouterStateSnapshot } from '@angular/router';
import { AppService } from './app/service/app.service';

@Injectable({ providedIn: 'root' })
export class AuthGuard {
    constructor(
        private router: Router,
        private service: AppService,
        // private authService: AuthService,
    ) {}

    async canActivate(state: RouterStateSnapshot) {
        const bearerToken = localStorage.getItem('auth_token');

        if (!bearerToken) {
            this.router.navigate(['/login']);
            return false;
        }

        return true;
    }
}
