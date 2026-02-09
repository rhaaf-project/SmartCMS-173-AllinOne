import { NgClass } from '@angular/common';
import { Component, Input, ViewChild, ViewContainerRef } from '@angular/core';
@Component({
    selector: 'icon-menu-microphone',
    template: `
        <ng-template #template>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" [ngClass]="class">
                <path opacity="0.5" d="M12 2C10.3431 2 9 3.34315 9 5V12C9 13.6569 10.3431 15 12 15C13.6569 15 15 13.6569 15 12V5C15 3.34315 13.6569 2 12 2Z" fill="currentColor"/>
                <path d="M6 10C6.55228 10 7 10.4477 7 11V12C7 14.7614 9.23858 17 12 17C14.7614 17 17 14.7614 17 12V11C17 10.4477 17.4477 10 18 10C18.5523 10 19 10.4477 19 11V12C19 15.5265 16.3923 18.4439 13 18.9291V21C13 21.5523 12.5523 22 12 22C11.4477 22 11 21.5523 11 21V18.9291C7.60771 18.4439 5 15.5265 5 12V11C5 10.4477 5.44772 10 6 10Z" fill="currentColor"/>
            </svg>
        </ng-template>
    `,
    imports: [NgClass],
})
export class IconMenuMicrophoneComponent {
    @Input() class: any = '';
    @ViewChild('template', { static: true }) template: any;
    constructor(private viewContainerRef: ViewContainerRef) { }
    ngOnInit() {
        this.viewContainerRef.createEmbeddedView(this.template);
        this.viewContainerRef.element.nativeElement.remove();
    }
}
