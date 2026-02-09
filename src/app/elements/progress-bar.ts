import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { NgIf } from '@angular/common';
import { HighlightModule } from 'ngx-highlightjs';
@Component({
    templateUrl: './progress-bar.html',
    imports: [FormsModule, HighlightModule, NgIf, IconCodeComponent],
})
export class ProgressBarComponent {
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
