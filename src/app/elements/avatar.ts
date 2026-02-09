import { Component } from '@angular/core';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { NgIf } from '@angular/common';
import { HighlightModule } from 'ngx-highlightjs';
import { NgxTippyModule } from 'ngx-tippy-wrapper';

@Component({
    templateUrl: './avatar.html',
    imports: [NgIf, HighlightModule, NgxTippyModule, IconCodeComponent],
})
export class AvatarComponent {
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
