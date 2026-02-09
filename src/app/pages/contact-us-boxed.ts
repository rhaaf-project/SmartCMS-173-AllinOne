import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { Store } from '@ngrx/store';
import { TranslateService } from '@ngx-translate/core';
import { toggleAnimation } from '../shared/animations';
import { AppService } from '../service/app.service';
import { IconCaretDownComponent } from '../shared/icon/icon-caret-down';
import { MenuModule } from 'headlessui-angular';
import { NgClass, NgFor } from '@angular/common';
import { IconUserComponent } from "../shared/icon/icon-user";
import { IconMailComponent } from "../shared/icon/icon-mail";
import { IconPhoneCallComponent } from "../shared/icon/icon-phone-call";
import { IconPencilComponent } from "../shared/icon/icon-pencil";
import { IconMessageDotsComponent } from "../shared/icon/icon-message-dots";

@Component({
    templateUrl: './contact-us-boxed.html',
    animations: [toggleAnimation],
    imports: [NgClass, NgFor, IconCaretDownComponent, MenuModule, IconUserComponent, IconMailComponent, IconPhoneCallComponent, IconPencilComponent, IconMessageDotsComponent],
})
export class ContactUsBoxedComponent {
    store: any;
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
