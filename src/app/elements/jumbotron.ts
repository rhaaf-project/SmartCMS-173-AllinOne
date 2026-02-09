import { Component } from '@angular/core';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { NgIf } from '@angular/common';
import { HighlightModule } from 'ngx-highlightjs';

@Component({
    templateUrl: './jumbotron.html',
    imports: [NgIf, HighlightModule, IconCodeComponent],
})
export class JumbotronComponent {
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
