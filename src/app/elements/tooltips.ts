import { Component } from '@angular/core';
import { Store } from '@ngrx/store';
import { IconBellComponent } from '../shared/icon/icon-bell';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { NgIf } from '@angular/common';
import { NgxTippyModule } from 'ngx-tippy-wrapper';
import { HighlightModule } from 'ngx-highlightjs';
@Component({
    templateUrl: './tooltips.html',
    imports: [NgIf, HighlightModule, IconBellComponent, IconCodeComponent, NgxTippyModule],
})
export class TooltipsComponent {
    codeArr: any = [];
    toggleCode = (name: string) => {
        if (this.codeArr.includes(name)) {
            this.codeArr = this.codeArr.filter((d: string) => d != name);
        } else {
            this.codeArr.push(name);
        }
    };

    constructor(public storeData: Store<any>) {
        this.initStore();
    }
    store: any;
    async initStore() {
        this.storeData
            .select((d) => d.index)
            .subscribe((d) => {
                this.store = d;
            });
    }
}
