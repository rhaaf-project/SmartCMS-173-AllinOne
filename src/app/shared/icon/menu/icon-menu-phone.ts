import { NgClass } from '@angular/common';
import { Component, Input, ViewChild, ViewContainerRef } from '@angular/core';
@Component({
    selector: 'icon-menu-phone',
    template: `
        <ng-template #template>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" [ngClass]="class">
                <path opacity="0.5" d="M17 2H7C5.89543 2 5 2.89543 5 4V20C5 21.1046 5.89543 22 7 22H17C18.1046 22 19 21.1046 19 20V4C19 2.89543 18.1046 2 17 2Z" fill="currentColor"/>
                <circle cx="12" cy="18" r="1.5" fill="currentColor"/>
                <path d="M9 5H15" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
            </svg>
        </ng-template>
    `,
    imports: [NgClass],
})
export class IconMenuPhoneComponent {
    @Input() class: any = '';
    @ViewChild('template', { static: true }) template: any;
    constructor(private viewContainerRef: ViewContainerRef) { }
    ngOnInit() {
        this.viewContainerRef.createEmbeddedView(this.template);
        this.viewContainerRef.element.nativeElement.remove();
    }
}
