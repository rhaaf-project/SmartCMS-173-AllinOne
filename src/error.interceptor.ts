// import { AuthService } from 'src/app/shared/auth.service';
import { Injectable } from '@angular/core';
import { HttpRequest, HttpHandler, HttpEvent, HttpInterceptor } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { TranslateService } from '@ngx-translate/core';
import { AppService } from './app/service/app.service';

@Injectable()
export class ErrorInterceptor implements HttpInterceptor {
    constructor(
        // private authService: AuthService,
        private service: AppService,
        public translate: TranslateService,
    ) {}

    intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
        return next.handle(req).pipe(
            catchError((err) => {
                let error = '';
                if (err?.error?.errors) {
                    const errors = err.error.errors;
                    for (const key in errors) {
                        if (errors.hasOwnProperty(key)) {
                            error += `${errors[key].join(' ')} `;
                        }
                    }
                } else {
                    error = err?.error?.detail || err?.error?.message || err?.message || err.statusText;
                }

                // if ([401].includes(err.status) && this.service.storeData?.user) {
                if ([401].includes(err.status)) {
                    // auto logout if 401 or 403 response is returned from the API
                    // this.authService.logout();
                } else {
                    const msg = this.translate.instant(error);
                    // this.service.toast(msg, 'error');
                }
                return throwError(() => error);
            }),
        );
    }
}
