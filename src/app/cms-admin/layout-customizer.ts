import { Component } from '@angular/core';
import { CommonModule, NgClass } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Store } from '@ngrx/store';
import { Router } from '@angular/router';
import { IconSunComponent } from '../shared/icon/icon-sun';
import { IconMoonComponent } from '../shared/icon/icon-moon';
import { IconLaptopComponent } from '../shared/icon/icon-laptop';

@Component({
    selector: 'app-layout-customizer',
    templateUrl: './layout-customizer.html',
    imports: [
        CommonModule,
        FormsModule,
        NgClass,
        IconSunComponent,
        IconMoonComponent,
        IconLaptopComponent,
    ],
})
export class LayoutCustomizerComponent {
    store: any;

    constructor(
        public storeData: Store<any>,
        public router: Router
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

    reloadRoute() {
        window.location.reload();
    }
}
