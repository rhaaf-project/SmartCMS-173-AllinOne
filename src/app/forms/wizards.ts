import { Component } from '@angular/core';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { NgClass, NgIf } from '@angular/common';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { IconHomeComponent } from '../shared/icon/icon-home';
import { IconUserComponent } from '../shared/icon/icon-user';
import { IconThumbUpComponent } from '../shared/icon/icon-thumb-up';
import { HighlightModule } from 'ngx-highlightjs';

@Component({
    templateUrl: './wizards.html',
    imports: [NgClass, NgIf, HighlightModule, FormsModule, ReactiveFormsModule, IconCodeComponent, IconHomeComponent, IconUserComponent, IconThumbUpComponent],
})
export class WizardsComponent {
    codeArr: any = [];
    toggleCode = (name: string) => {
        if (this.codeArr.includes(name)) {
            this.codeArr = this.codeArr.filter((d: string) => d != name);
        } else {
            this.codeArr.push(name);
        }
    };

    constructor() {}

    activeTab1 = 1;
    activeTab2 = 1;
    activeTab3 = 1;
    activeTab4 = 1;
    activeTab5 = 1;
    activeTab6 = 1;
    activeTab7 = 1;
}
