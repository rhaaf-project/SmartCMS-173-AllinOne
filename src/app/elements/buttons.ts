import { Component } from '@angular/core';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { NgIf } from '@angular/common';
import { IconSettingsComponent } from '../shared/icon/icon-settings';
import { IconPencilComponent } from '../shared/icon/icon-pencil';
import { IconDownloadComponent } from '../shared/icon/icon-download';
import { IconSunComponent } from '../shared/icon/icon-sun';
import { HighlightModule } from 'ngx-highlightjs';

@Component({
    templateUrl: './buttons.html',
    imports: [NgIf, HighlightModule, IconCodeComponent, IconSettingsComponent, IconPencilComponent, IconDownloadComponent, IconSunComponent],
})
export class ButtonsComponent {
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
