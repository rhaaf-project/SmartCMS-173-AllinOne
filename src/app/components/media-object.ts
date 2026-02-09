import { Component } from '@angular/core';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { NgIf } from '@angular/common';
import { toggleAnimation } from '../shared/animations';
import { IconMessageDotsComponent } from '../shared/icon/icon-message-dots';
import { IconPencilComponent } from '../shared/icon/icon-pencil';
import { IconTrashLinesComponent } from '../shared/icon/icon-trash-lines';
import { IconChatDotComponent } from '../shared/icon/icon-chat-dot';
import { IconPhoneComponent } from '../shared/icon/icon-phone';
import { IconBarChartComponent } from '../shared/icon/icon-bar-chart';
import { MenuModule } from 'headlessui-angular';
import { IconHorizontalDotsComponent } from '../shared/icon/icon-horizontal-dots';
import { IconXCircleComponent } from '../shared/icon/icon-x-circle';
import { IconInfoTriangleComponent } from '../shared/icon/icon-info-triangle';
import { HighlightModule } from 'ngx-highlightjs';

@Component({
    templateUrl: './media-object.html',
    animations: [toggleAnimation],
    imports: [
        NgIf,
        HighlightModule,
        IconCodeComponent,
        IconMessageDotsComponent,
        IconPencilComponent,
        IconTrashLinesComponent,
        IconChatDotComponent,
        IconPhoneComponent,
        IconBarChartComponent,
        MenuModule,
        IconHorizontalDotsComponent,
        IconXCircleComponent,
        IconInfoTriangleComponent,
    ],
})
export class MediaObjectComponent {
    codeArr: any = [];
    toggleCode = (name: string) => {
        if (this.codeArr.includes(name)) {
            this.codeArr = this.codeArr.filter((d: string) => d != name);
        } else {
            this.codeArr.push(name);
        }
    };

    constructor() {}
}
