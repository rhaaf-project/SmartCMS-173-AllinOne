import { Component } from '@angular/core';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { NgIf } from '@angular/common';
import { toggleAnimation } from '../shared/animations';
import { IconCaretDownComponent } from '../shared/icon/icon-caret-down';
import { MenuModule } from 'headlessui-angular';
import { HighlightModule } from 'ngx-highlightjs';

@Component({
    templateUrl: './buttons-group.html',
    animations: [toggleAnimation],
    imports: [NgIf, HighlightModule, IconCodeComponent, IconCaretDownComponent, MenuModule],
})
export class ButtonsGroupComponent {
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
