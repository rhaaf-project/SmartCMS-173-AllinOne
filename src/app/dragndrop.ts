import { Component } from '@angular/core';
import { IconBellComponent } from './shared/icon/icon-bell';
import { SortablejsModule } from '@dustfoundation/ngx-sortablejs';
import { CommonModule } from '@angular/common';
import { IconStarComponent } from "./shared/icon/icon-star";
import { IconHeartComponent } from "./shared/icon/icon-heart";

@Component({
    templateUrl: './dragndrop.html',
    imports: [CommonModule, SortablejsModule, IconBellComponent, IconStarComponent, IconHeartComponent],
})
export class DragndropComponent {
    constructor() {}
    items = [
        {
            id: 1,
            text: 'Need to be approved',
            name: 'Kelly Young',
        },
        {
            id: 2,
            text: 'Meeting with client',
            name: 'Andy King',
        },
        {
            id: 3,
            text: 'Project Detail',
            name: 'Judy Holmes',
        },
        {
            id: 4,
            text: 'Edited Post Apporval',
            name: 'Vincent Carpenter',
        },
        {
            id: 5,
            text: 'Project Lead Pickup',
            name: 'Mary McDonald',
        },
    ];
}
