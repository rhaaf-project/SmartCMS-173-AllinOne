import { Component } from '@angular/core';
import { NgIf } from '@angular/common';
import { CountUpModule } from 'ngx-countup';
import { IconBellComponent } from '../shared/icon/icon-bell';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { IconUsersComponent } from '../shared/icon/icon-users';
import { IconCloudDownloadComponent } from '../shared/icon/icon-cloud-download';
import { IconAwardComponent } from '../shared/icon/icon-award';
import { HighlightModule } from 'ngx-highlightjs';

@Component({
    templateUrl: './counter.html',
    imports: [NgIf, HighlightModule, CountUpModule, IconBellComponent, IconCodeComponent, IconUsersComponent, IconCloudDownloadComponent, IconAwardComponent],
})
export class CounterComponent {
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
