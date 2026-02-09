import { Component } from '@angular/core';
import { toggleAnimation } from '../shared/animations';
import { IconBellComponent } from '../shared/icon/icon-bell';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { NgIf } from '@angular/common';
import { IconCaretDownComponent } from '../shared/icon/icon-caret-down';
import { MenuModule } from 'headlessui-angular';
import { IconHorizontalDotsComponent } from '../shared/icon/icon-horizontal-dots';
import { HighlightModule } from 'ngx-highlightjs';

@Component({
    templateUrl: './dropdown.html',
    animations: [toggleAnimation],
    imports: [NgIf, HighlightModule, IconBellComponent, IconCodeComponent, IconCaretDownComponent, MenuModule, IconHorizontalDotsComponent],
})
export class DropdownComponent {
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
