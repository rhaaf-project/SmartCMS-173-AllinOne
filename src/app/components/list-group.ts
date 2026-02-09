import { Component } from '@angular/core';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { NgIf } from '@angular/common';
import { IconMailComponent } from '../shared/icon/icon-mail';
import { IconMapPinComponent } from '../shared/icon/icon-map-pin';
import { IconDropletComponent } from '../shared/icon/icon-droplet';
import { HighlightModule } from 'ngx-highlightjs';

@Component({
    templateUrl: './list-group.html',
    imports: [NgIf, HighlightModule, IconCodeComponent, IconMailComponent, IconMapPinComponent, IconDropletComponent],
})
export class ListGroupComponent {
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
