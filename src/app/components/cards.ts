import { Component } from '@angular/core';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { IconDropletComponent } from '../shared/icon/icon-droplet';
import { NgIf } from '@angular/common';
import { IconStarComponent } from '../shared/icon/icon-star';
import { IconHeartComponent } from '../shared/icon/icon-heart';
import { IconEyeComponent } from '../shared/icon/icon-eye';
import { HighlightModule } from 'ngx-highlightjs';

@Component({
    templateUrl: './cards.html',
    imports: [NgIf, HighlightModule, IconCodeComponent, IconDropletComponent, IconStarComponent, IconHeartComponent, IconEyeComponent],
})
export class CardsComponent {
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
