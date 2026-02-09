import { Injectable } from '@angular/core';
import { HttpEvent, HttpInterceptor, HttpHandler, HttpRequest } from '@angular/common/http';
import { Observable } from 'rxjs';
import { AppService } from './app/service/app.service';

@Injectable({ providedIn: 'root' })
export class JwtInterceptor implements HttpInterceptor {
    constructor(private service: AppService) {}

    intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
        // const bearerToken = this.service.get_localstorage('auth_token');
        // if (bearerToken) {
        //     req = req.clone({
        //         headers: req.headers.set('Authorization', `Bearer ${bearerToken}`),
        //     });
        // }

        return next.handle(req);
    }
}
