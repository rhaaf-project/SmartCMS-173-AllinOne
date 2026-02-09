import { Component } from '@angular/core';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { IconGlobeComponent } from '../shared/icon/icon-globe';
import { IconGalleryComponent } from '../shared/icon/icon-gallery';
import { IconTxtFileComponent } from '../shared/icon/icon-txt-file';
import { NgIf } from '@angular/common';
import { HighlightModule } from 'ngx-highlightjs';

@Component({
    templateUrl: './timeline.html',
    imports: [NgIf, HighlightModule, IconCodeComponent, IconGlobeComponent, IconGalleryComponent, IconTxtFileComponent],
})
export class TimelineComponent {
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
