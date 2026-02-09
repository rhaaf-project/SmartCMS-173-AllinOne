import { Component } from '@angular/core';
import { Store } from '@ngrx/store';
import Swiper from 'swiper';
import { Navigation, Pagination } from 'swiper/modules';
import { IconBellComponent } from '../shared/icon/icon-bell';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { NgxCustomModalComponent } from 'ngx-custom-modal';
import { NgClass, NgFor, NgIf } from '@angular/common';
import { IconUserComponent } from '../shared/icon/icon-user';
import { IconLockComponent } from '../shared/icon/icon-lock';
import { IconFacebookComponent } from '../shared/icon/icon-facebook';
import { IconGithubComponent } from '../shared/icon/icon-github';
import { IconAtComponent } from '../shared/icon/icon-at';
import { IconCaretDownComponent } from '../shared/icon/icon-caret-down';
import { HighlightModule } from 'ngx-highlightjs';

@Component({
    templateUrl: './modals.html',
    imports: [
        NgIf,
        NgClass,
        NgFor,
        HighlightModule,
        IconBellComponent,
        IconCodeComponent,
        NgxCustomModalComponent,
        IconUserComponent,
        IconLockComponent,
        IconFacebookComponent,
        IconGithubComponent,
        IconAtComponent,
        IconCaretDownComponent,
    ],
})
export class ModalsComponent {
    codeArr: any = [];
    toggleCode = (name: string) => {
        if (this.codeArr.includes(name)) {
            this.codeArr = this.codeArr.filter((d: string) => d != name);
        } else {
            this.codeArr.push(name);
        }
    };
    constructor(public storeData: Store<any>) {
        this.initStore();
    }
    store: any;
    async initStore() {
        this.storeData
            .select((d) => d.index)
            .subscribe((d) => {
                this.store = d;
            });
    }

    tab1: string = 'home';
    swiper1: any;
    items = ['carousel1.jpeg', 'carousel2.jpeg', 'carousel3.jpeg'];

    initSwiper() {
        setTimeout(() => {
            this.swiper1 = new Swiper('#slider1', {
                modules: [Navigation, Pagination],
                navigation: { nextEl: '.swiper-button-next-ex1', prevEl: '.swiper-button-prev-ex1' },
                pagination: {
                    el: '#slider1 .swiper-pagination',
                    type: 'bullets',
                    clickable: true,
                },
            });
        });
    }
}
