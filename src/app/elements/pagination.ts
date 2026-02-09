import { Component } from '@angular/core';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { NgIf } from '@angular/common';
import { IconCaretsDownComponent } from '../shared/icon/icon-carets-down';
import { IconCaretDownComponent } from '../shared/icon/icon-caret-down';
import { HighlightModule } from 'ngx-highlightjs';

@Component({
    templateUrl: './pagination.html',
    imports: [NgIf, HighlightModule, IconCodeComponent, IconCaretsDownComponent, IconCaretDownComponent],
})
export class PaginationComponent {
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
