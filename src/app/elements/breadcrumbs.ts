import { Component } from '@angular/core';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { NgIf } from '@angular/common';
import { IconHomeComponent } from '../shared/icon/icon-home';
import { IconBoxComponent } from '../shared/icon/icon-box';
import { IconCpuBoltComponent } from '../shared/icon/icon-cpu-bolt';
import { HighlightModule } from 'ngx-highlightjs';

@Component({
    templateUrl: './breadcrumbs.html',
    imports: [NgIf, HighlightModule, IconCodeComponent, IconHomeComponent, IconBoxComponent, IconCpuBoltComponent],
})
export class BreadcrumbsComponent {
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
