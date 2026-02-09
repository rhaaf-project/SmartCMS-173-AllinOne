import { NgIf } from '@angular/common';
import { Component } from '@angular/core';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import Swal from 'sweetalert2';
import { ClipboardModule } from 'ngx-clipboard';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { IconBellComponent } from '../shared/icon/icon-bell';
import { IconPencilComponent } from '../shared/icon/icon-pencil';
import { IconCopyComponent } from '../shared/icon/icon-copy';
import { HighlightModule } from 'ngx-highlightjs';

@Component({
    templateUrl: './clipboard.html',
    imports: [
        NgIf,
        HighlightModule,
        FormsModule,
        ReactiveFormsModule,
        ClipboardModule,
        IconCodeComponent,
        IconBellComponent,
        IconPencilComponent,
        IconCopyComponent,
    ],
})
export class ClipboardComponent {
    codeArr: any = [];
    toggleCode = (name: string) => {
        if (this.codeArr.includes(name)) {
            this.codeArr = this.codeArr.filter((d: string) => d != name);
        } else {
            this.codeArr.push(name);
        }
    };

    constructor() {}

    message1 = 'http://www.admin-dashboard.com';
    message2 = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit...';

    showMessage(msg = '', type = 'success') {
        const toast: any = Swal.mixin({
            toast: true,
            position: 'top',
            showConfirmButton: false,
            timer: 3000,
            customClass: { container: 'toast' },
        });
        toast.fire({
            icon: type,
            title: msg,
            padding: '10px 20px',
        });
    }
}
