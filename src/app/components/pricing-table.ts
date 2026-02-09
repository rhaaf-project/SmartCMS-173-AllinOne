import { Component } from '@angular/core';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { IconArrowLeftComponent } from '../shared/icon/icon-arrow-left';
import { NgClass, NgIf } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HighlightModule } from 'ngx-highlightjs';

@Component({
    templateUrl: './pricing-table.html',
    imports: [FormsModule, NgClass, NgIf, HighlightModule, IconCodeComponent, IconArrowLeftComponent],
})
export class PricingTableComponent {
    codeArr: any = [];
    toggleCode = (name: string) => {
        if (this.codeArr.includes(name)) {
            this.codeArr = this.codeArr.filter((d: string) => d != name);
        } else {
            this.codeArr.push(name);
        }
    };

    constructor() {}
    yearlyPrice: Boolean = false;
}
