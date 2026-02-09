import { Component } from '@angular/core';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { NgClass, NgIf } from '@angular/common';
import { IconHomeComponent } from '../shared/icon/icon-home';
import { IconUserComponent } from '../shared/icon/icon-user';
import { IconPhoneComponent } from '../shared/icon/icon-phone';
import { IconInfoCircleComponent } from '../shared/icon/icon-info-circle';
import { IconSettingsComponent } from '../shared/icon/icon-settings';
import { HighlightModule } from 'ngx-highlightjs';

@Component({
    templateUrl: './tabs.html',
    imports: [
        NgIf,
        HighlightModule,
        IconCodeComponent,
        NgClass,
        IconHomeComponent,
        IconUserComponent,
        IconPhoneComponent,
        IconInfoCircleComponent,
        IconSettingsComponent,
    ],
})
export class TabsComponent {
    codeArr: any = [];
    toggleCode = (name: string) => {
        if (this.codeArr.includes(name)) {
            this.codeArr = this.codeArr.filter((d: string) => d != name);
        } else {
            this.codeArr.push(name);
        }
    };

    tab1: string = 'home';
    tab2: string = 'home';
    tab3: string = 'home';
    tab4: string = 'home';
    tab5: string = 'home';
    tab6: string = 'home';
    tab7: string = 'home';
    tab8: string = 'home';
    tab9: string = 'home';
    tab10: string = 'home';
    tab11: string = 'home';
    tab12: string = 'home';
    tab13: string = 'home';
    tab14: string = 'home';
    tab15: string = 'home';
    tab16: string = 'home';
    tab17: string = 'home';
    tab18: string = 'home';
    tab19: string = 'home';
    tab20: string = 'home';
    tab21: string = 'home';
    tab22: string = 'home';

    constructor() {}
}
