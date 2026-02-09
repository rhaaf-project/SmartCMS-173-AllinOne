import { Component } from '@angular/core';
import { slideDownUp } from '../shared/animations';
import { Store } from '@ngrx/store';
import { IconArrowWaveLeftUpComponent } from '../shared/icon/icon-arrow-wave-left-up';
import { NgClass, NgIf } from '@angular/common';
import { IconDesktopComponent } from '../shared/icon/icon-desktop';
import { IconUserComponent } from '../shared/icon/icon-user';
import { IconBoxComponent } from '../shared/icon/icon-box';
import { IconDollarSignCircleComponent } from '../shared/icon/icon-dollar-sign-circle';
import { IconRouterComponent } from '../shared/icon/icon-router';
import { IconPlusCircleComponent } from '../shared/icon/icon-plus-circle';
import { IconMinusCircleComponent } from '../shared/icon/icon-minus-circle';

@Component({
    templateUrl: './faq.html',
    animations: [slideDownUp],
    imports: [
        NgClass,
        NgIf,
        IconArrowWaveLeftUpComponent,
        IconDesktopComponent,
        IconUserComponent,
        IconBoxComponent,
        IconDollarSignCircleComponent,
        IconRouterComponent,
        IconPlusCircleComponent,
        IconMinusCircleComponent,
    ],
})
export class FaqComponent {
    store: any;
    constructor(public storeData: Store<any>) {
        this.initStore();
    }
    async initStore() {
        this.storeData
            .select((d) => d.index)
            .subscribe((d) => {
                this.store = d;
            });
    }
    activeTab: any = 'general';
    active1: any = 1;
    active2: any = 1;
}
