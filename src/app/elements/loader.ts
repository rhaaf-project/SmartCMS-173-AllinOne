import { Component } from '@angular/core';
import { IconLoadingComponent } from '../shared/icon/icon-loader';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { NgIf } from '@angular/common';
import { HighlightModule } from 'ngx-highlightjs';

@Component({
    templateUrl: './loader.html',
    imports: [NgIf, HighlightModule, IconLoadingComponent, IconCodeComponent],
})
export class LoaderComponent {
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
