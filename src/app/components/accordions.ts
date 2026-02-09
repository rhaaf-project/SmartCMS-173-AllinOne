import { Component } from '@angular/core';
import { slideDownUp } from '../shared/animations';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { NgClass, NgIf } from '@angular/common';
import { IconCaretDownComponent } from '../shared/icon/icon-caret-down';
import { IconAirplayComponent } from '../shared/icon/icon-airplay';
import { IconBoxComponent } from '../shared/icon/icon-box';
import { IconLayoutComponent } from '../shared/icon/icon-layout';
import { HighlightModule } from 'ngx-highlightjs';

@Component({
    templateUrl: './accordions.html',
    animations: [slideDownUp],
    imports: [HighlightModule, IconCodeComponent, NgClass, NgIf, IconCaretDownComponent, IconAirplayComponent, IconBoxComponent, IconLayoutComponent],
})
export class AccordionsComponent {
    codeArr: any = [];
    toggleCode = (name: string) => {
        if (this.codeArr.includes(name)) {
            this.codeArr = this.codeArr.filter((d: string) => d != name);
        } else {
            this.codeArr.push(name);
        }
    };

    constructor() {}

    accordians1: any = 1;
    accordians2: any = 1;
    accordians3: any = 1;
    accordians4: any = 1;
}
