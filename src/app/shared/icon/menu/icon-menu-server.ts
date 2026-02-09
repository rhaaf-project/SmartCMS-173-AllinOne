import { NgClass } from '@angular/common';
import { Component, Input, ViewChild, ViewContainerRef } from '@angular/core';
@Component({
    selector: 'icon-menu-server',
    template: `
        <ng-template #template>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" [ngClass]="class">
                <path opacity="0.5" d="M2 6C2 4.89543 2.89543 4 4 4H20C21.1046 4 22 4.89543 22 6V8C22 9.10457 21.1046 10 20 10H4C2.89543 10 2 9.10457 2 8V6Z" fill="currentColor"/>
                <path d="M2 16C2 14.8954 2.89543 14 4 14H20C21.1046 14 22 14.8954 22 16V18C22 19.1046 21.1046 20 20 20H4C2.89543 20 2 19.1046 2 18V16Z" fill="currentColor"/>
                <circle cx="6" cy="7" r="1" fill="currentColor"/>
                <circle cx="6" cy="17" r="1" fill="currentColor"/>
            </svg>
        </ng-template>
    `,
    imports: [NgClass],
})
export class IconMenuServerComponent {
    @Input() class: any = '';
    @ViewChild('template', { static: true }) template: any;
    constructor(private viewContainerRef: ViewContainerRef) { }
    ngOnInit() {
        this.viewContainerRef.createEmbeddedView(this.template);
        this.viewContainerRef.element.nativeElement.remove();
    }
}
