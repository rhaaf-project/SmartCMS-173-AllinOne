import { Component } from '@angular/core';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { NgIf } from '@angular/common';
import { IconXComponent } from '../shared/icon/icon-x';
import { IconInfoTriangleComponent } from '../shared/icon/icon-info-triangle';
import { IconBellBingComponent } from '../shared/icon/icon-bell-bing';
import { IconInfoCircleComponent } from '../shared/icon/icon-info-circle';
import { IconSettingsComponent } from '../shared/icon/icon-settings';
import { HighlightModule } from 'ngx-highlightjs';

@Component({
    templateUrl: './alerts.html',
    imports: [
        NgIf,
        HighlightModule,
        IconCodeComponent,
        IconXComponent,
        IconInfoTriangleComponent,
        IconBellBingComponent,
        IconInfoCircleComponent,
        IconSettingsComponent,
    ],
})
export class AlertsComponent {
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
