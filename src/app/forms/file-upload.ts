import { NgIf } from '@angular/common';
import { Component } from '@angular/core';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { FileUploadWithPreview } from 'file-upload-with-preview';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { IconBellComponent } from '../shared/icon/icon-bell';
import { HighlightModule } from 'ngx-highlightjs';

@Component({
    templateUrl: './file-upload.html',
    imports: [NgIf, HighlightModule, FormsModule, ReactiveFormsModule, IconCodeComponent, IconBellComponent],
})
export class FileUploadComponent {
    codeArr: any = [];
    toggleCode = (name: string) => {
        if (this.codeArr.includes(name)) {
            this.codeArr = this.codeArr.filter((d: string) => d != name);
        } else {
            this.codeArr.push(name);
        }
    };

    constructor() {}

    ngOnInit() {
        // single image upload
        new FileUploadWithPreview('myFirstImage', {
            images: {
                baseImage: '/assets/images/file-preview.svg',
                backgroundImage: '',
            },
        });

        // multiple image upload
        new FileUploadWithPreview('mySecondImage', {
            images: {
                baseImage: '/assets/images/file-preview.svg',
                backgroundImage: '',
            },
            multiple: true,
        });
    }
}
