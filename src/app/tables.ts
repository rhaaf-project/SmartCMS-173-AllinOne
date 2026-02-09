import { Component } from '@angular/core';
import { toggleAnimation } from './shared/animations';
import { CommonModule } from '@angular/common';
import { IconCodeComponent } from './shared/icon/icon-code';
import { IconTrashLinesComponent } from './shared/icon/icon-trash-lines';
import { IconXCircleComponent } from './shared/icon/icon-x-circle';
import { IconPencilComponent } from './shared/icon/icon-pencil';
import { IconHorizontalDotsComponent } from './shared/icon/icon-horizontal-dots';
import { MenuModule } from 'headlessui-angular';
import { IconCircleCheckComponent } from './shared/icon/icon-circle-check';
import { IconSettingsComponent } from './shared/icon/icon-settings';
import { NgScrollbarModule } from 'ngx-scrollbar';
import { HighlightModule } from 'ngx-highlightjs';

@Component({
    templateUrl: './tables.html',
    animations: [toggleAnimation],
    imports: [
        CommonModule,
        NgScrollbarModule,
        MenuModule,
        HighlightModule,
        IconCodeComponent,
        IconTrashLinesComponent,
        IconXCircleComponent,
        IconPencilComponent,
        IconHorizontalDotsComponent,
        IconCircleCheckComponent,
        IconSettingsComponent,
    ],
})
export class TablesComponent {
    codeArr: any = [];
    toggleCode = (name: string) => {
        if (this.codeArr.includes(name)) {
            this.codeArr = this.codeArr.filter((d: string) => d != name);
        } else {
            this.codeArr.push(name);
        }
    };

    tableData = [
        {
            id: 1,
            name: 'John Doe',
            email: 'johndoe@yahoo.com',
            date: '10/08/2020',
            sale: 120,
            status: 'Complete',
            register: '5 min ago',
            progress: '40%',
            position: 'Developer',
            office: 'London',
        },
        {
            id: 2,
            name: 'Shaun Park',
            email: 'shaunpark@gmail.com',
            date: '11/08/2020',
            sale: 400,
            status: 'Pending',
            register: '11 min ago',
            progress: '23%',
            position: 'Designer',
            office: 'New York',
        },
        {
            id: 3,
            name: 'Alma Clarke',
            email: 'alma@gmail.com',
            date: '12/02/2020',
            sale: 310,
            status: 'In Progress',
            register: '1 hour ago',
            progress: '80%',
            position: 'Accountant',
            office: 'Amazon',
        },
        {
            id: 4,
            name: 'Vincent Carpenter',
            email: 'vincent@gmail.com',
            date: '13/08/2020',
            sale: 100,
            status: 'Canceled',
            register: '1 day ago',
            progress: '60%',
            position: 'Data Scientist',
            office: 'Canada',
        },
    ];
    constructor() {}
}
