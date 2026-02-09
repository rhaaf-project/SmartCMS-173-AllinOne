import { NgClass } from '@angular/common';
import { Component, Input, ViewChild, ViewContainerRef } from '@angular/core';
@Component({
    selector: 'icon-menu-user-group',
    template: `
        <ng-template #template>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" [ngClass]="class">
                <circle cx="9" cy="6" r="4" fill="currentColor"/>
                <circle opacity="0.5" cx="17" cy="7" r="3" fill="currentColor"/>
                <ellipse cx="9" cy="17" rx="7" ry="4" fill="currentColor"/>
                <path opacity="0.5" d="M21 18C21 16.1362 19.4183 14.5701 17 14.126" fill="currentColor"/>
                <path opacity="0.5" d="M21 18C21 16.1362 19.4183 14.5701 17 14.126" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
            </svg>
        </ng-template>
    `,
    imports: [NgClass],
})
export class IconMenuUserGroupComponent {
    @Input() class: any = '';
    @ViewChild('template', { static: true }) template: any;
    constructor(private viewContainerRef: ViewContainerRef) { }
    ngOnInit() {
        this.viewContainerRef.createEmbeddedView(this.template);
        this.viewContainerRef.element.nativeElement.remove();
    }
}
