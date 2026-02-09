import { Component } from '@angular/core';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { NgIf } from '@angular/common';
import { IconFacebookComponent } from '../shared/icon/icon-facebook';
import { IconSettingsComponent } from '../shared/icon/icon-settings';
import { HighlightModule } from 'ngx-highlightjs';

@Component({
    templateUrl: './badges.html',
    imports: [NgIf, HighlightModule, IconCodeComponent, IconFacebookComponent, IconSettingsComponent],
})
export class BadgesComponent {
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
