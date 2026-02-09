import { Component } from '@angular/core';
import { toggleAnimation } from '../shared/animations';
import { NgIf } from '@angular/common';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { IconBellBingComponent } from '../shared/icon/icon-bell-bing';
import { IconLoadingComponent } from '../shared/icon/icon-loader';
import { IconSettingsComponent } from '../shared/icon/icon-settings';
import { MenuModule } from 'headlessui-angular';
import { IconCaretDownComponent } from '../shared/icon/icon-caret-down';
import { HighlightModule } from 'ngx-highlightjs';

@Component({
    templateUrl: './input-group.html',
    imports: [
        NgIf,
        HighlightModule,
        FormsModule,
        ReactiveFormsModule,
        IconCodeComponent,
        IconBellBingComponent,
        IconLoadingComponent,
        IconSettingsComponent,
        MenuModule,
        IconCaretDownComponent,
    ],
    animations: [toggleAnimation],
})
export class InputGroupComponent {
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
