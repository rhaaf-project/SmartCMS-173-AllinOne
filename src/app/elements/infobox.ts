import { Component } from '@angular/core';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { IconBoxComponent } from '../shared/icon/icon-box';
import { IconArrowLeftComponent } from '../shared/icon/icon-arrow-left';
import { NgIf } from '@angular/common';
import { HighlightModule } from 'ngx-highlightjs';

@Component({
    templateUrl: './infobox.html',
    imports: [NgIf, HighlightModule, IconCodeComponent, IconBoxComponent, IconArrowLeftComponent],
})
export class InfoboxComponent {
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
