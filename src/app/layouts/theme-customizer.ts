import { Component } from '@angular/core';
import { Store } from '@ngrx/store';
import { Router } from '@angular/router';
import { NgClass } from '@angular/common';
import { IconSettingsComponent } from '../shared/icon/icon-settings';
import { NgScrollbarModule } from 'ngx-scrollbar';
import { IconXComponent } from '../shared/icon/icon-x';
import { IconSunComponent } from '../shared/icon/icon-sun';
import { IconMoonComponent } from '../shared/icon/icon-moon';
import { IconLaptopComponent } from '../shared/icon/icon-laptop';
import { FormsModule } from '@angular/forms';

@Component({
    selector: 'setting',
    templateUrl: './theme-customizer.html',
    imports: [FormsModule, NgClass, NgScrollbarModule, IconSettingsComponent, IconXComponent, IconSunComponent, IconMoonComponent, IconLaptopComponent],
})
export class ThemeCustomizerComponent {
    store: any;
    showCustomizer = false;
    constructor(
        public storeData: Store<any>,
        public router: Router,
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

    setPrimaryColor(color: any) {
        this.storeData.dispatch({ type: 'togglePrimaryColor', payload: color });
    }

    reloadRoute() {
        window.location.reload();
        this.showCustomizer = true;
    }
}
