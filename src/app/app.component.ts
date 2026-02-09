import { Component } from '@angular/core';
import { Title } from '@angular/platform-browser';
import { ActivatedRoute, NavigationEnd, Router, RouterOutlet } from '@angular/router';
import { Store } from '@ngrx/store';
import { filter, map, switchMap, tap } from 'rxjs/operators';

@Component({
    selector: 'app-root',
    templateUrl: './app.component.html',
    imports: [RouterOutlet],
})
export class AppComponent {
    constructor(
        private router: Router,
        private activatedRoute: ActivatedRoute,
        private titleService: Title,
        public storeData: Store<any>,
    ) {
        this.storeData
            .select((d) => d.index)
            .subscribe((d) => {
                const body: any = document.querySelector('body');
                body.classList.remove('theme-orange', 'theme-yellow', 'theme-red', 'theme-green', 'theme-purple', 'theme-cyan');
                if (d.primaryColor && d.primaryColor !== 'blue') {
                    body.classList.add('theme-' + d.primaryColor);
                }
            });
        this.router.events
            .pipe(
                filter((event) => event instanceof NavigationEnd),
                map(() => this.activatedRoute),
                map((route) => {
                    while (route.firstChild) route = route.firstChild;
                    return route;
                }),
                filter((route) => route.outlet === 'primary'),
                switchMap((route) => {
                    return route.data.pipe(
                        map((routeData: any) => {
                            const title = routeData['title'];
                            return { title };
                        }),
                    );
                }),
                tap((data: any) => {
                    let title = data.title;
                    title = (title ? title + ' | ' : '') + 'SmartUCX Admin';
                    this.titleService.setTitle(title);
                }),
            )
            .subscribe();
    }
}
