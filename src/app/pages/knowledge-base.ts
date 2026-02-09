import { Component } from '@angular/core';
import { slideDownUp } from '../shared/animations';
import { IconArrowWaveLeftUpComponent } from '../shared/icon/icon-arrow-wave-left-up';
import { IconDesktopComponent } from '../shared/icon/icon-desktop';
import { NgClass, NgFor, NgIf } from '@angular/common';
import { IconUserComponent } from '../shared/icon/icon-user';
import { IconBoxComponent } from '../shared/icon/icon-box';
import { IconDollarSignCircleComponent } from '../shared/icon/icon-dollar-sign-circle';
import { IconRouterComponent } from '../shared/icon/icon-router';
import { IconPlusCircleComponent } from '../shared/icon/icon-plus-circle';
import { IconMinusCircleComponent } from '../shared/icon/icon-minus-circle';
import { IconPlayCircleComponent } from '../shared/icon/icon-play-circle';
import { NgxCustomModalComponent } from 'ngx-custom-modal';

@Component({
    templateUrl: './knowledge-base.html',
    animations: [slideDownUp],
    imports: [
        NgClass,
        NgFor,
        NgIf,
        IconArrowWaveLeftUpComponent,
        IconDesktopComponent,
        IconUserComponent,
        IconBoxComponent,
        IconDollarSignCircleComponent,
        IconRouterComponent,
        IconPlusCircleComponent,
        IconMinusCircleComponent,
        IconPlayCircleComponent,
        NgxCustomModalComponent,
    ],
})
export class KnowledgeBaseComponent {
    constructor() {}
    activeTab: any = 'general';
    active1: any = 1;
    active2: any = 1;
    modal = false;
    items = [
        {
            src: '/assets/images/knowledge/image-5.jpg',
            title: 'Excessive sugar is harmful',
        },
        {
            src: '/assets/images/knowledge/image-6.jpg',
            title: 'Creative Photography',
        },
        {
            src: '/assets/images/knowledge/image-7.jpg',
            title: 'Plan your next trip',
        },
        {
            src: '/assets/images/knowledge/image-8.jpg',
            title: 'My latest Vlog',
        },
    ];
}
