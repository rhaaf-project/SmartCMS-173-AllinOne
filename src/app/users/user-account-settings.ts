import { Component } from '@angular/core';
import { IconHomeComponent } from '../shared/icon/icon-home';
import { IconDollarSignCircleComponent } from '../shared/icon/icon-dollar-sign-circle';
import { IconUserComponent } from '../shared/icon/icon-user';
import { IconPhoneComponent } from '../shared/icon/icon-phone';
import { NgClass, NgIf } from '@angular/common';
import { IconLinkedinComponent } from "../shared/icon/icon-linkedin";
import { IconTwitterComponent } from "../shared/icon/icon-twitter";
import { IconFacebookComponent } from "../shared/icon/icon-facebook";
import { IconGithubComponent } from "../shared/icon/icon-github";

@Component({
    templateUrl: './user-account-settings.html',
    imports: [NgClass, NgIf, IconHomeComponent, IconDollarSignCircleComponent, IconUserComponent, IconPhoneComponent, IconLinkedinComponent, IconTwitterComponent, IconFacebookComponent, IconGithubComponent],
})
export class UserAccountSettingsComponent {
    activeTab = 'home';
    constructor() {}
}
