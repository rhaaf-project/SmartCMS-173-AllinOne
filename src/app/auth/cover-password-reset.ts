import { Component } from '@angular/core';
import { Router, RouterModule } from '@angular/router';
import { Store } from '@ngrx/store';
import { TranslateService } from '@ngx-translate/core';
import { toggleAnimation } from '../shared/animations';
import { AppService } from '../service/app.service';
import { IconCaretDownComponent } from '../shared/icon/icon-caret-down';
import { MenuModule } from 'headlessui-angular';
import { NgClass, NgFor } from '@angular/common';
import { IconMailComponent } from '../shared/icon/icon-mail';

@Component({
    templateUrl: './cover-password-reset.html',
    animations: [toggleAnimation],
    imports: [RouterModule, NgClass, NgFor, IconCaretDownComponent, MenuModule, IconMailComponent],
})
export class CoverPasswordResetComponent {
    store: any;
    currYear: number = new Date().getFullYear();
    constructor(
        public translate: TranslateService,
        public storeData: Store<any>,
        public router: Router,
        private appSetting: AppService,
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
