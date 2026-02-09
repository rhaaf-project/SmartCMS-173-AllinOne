import { NgIf } from '@angular/common';
import { Component } from '@angular/core';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { HighlightModule } from 'ngx-highlightjs';

@Component({
    templateUrl: './checkbox-radio.html',
    imports: [NgIf, HighlightModule, FormsModule, ReactiveFormsModule, IconCodeComponent],
})
export class CheckboxRadioComponent {
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
