import { NgClass } from '@angular/common';
import { Component, Input, ViewChild, ViewContainerRef } from '@angular/core';
@Component({
    selector: 'icon-menu-signal',
    template: `
        <ng-template #template>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" [ngClass]="class">
                <path opacity="0.5" d="M3 18V21H6V18H3Z" fill="currentColor"/>
                <path opacity="0.7" d="M3 18V21H6V18H3ZM8 14V21H11V14H8Z" fill="currentColor"/>
                <path d="M13 10V21H16V10H13Z" fill="currentColor"/>
                <path d="M18 6V21H21V6H18Z" fill="currentColor"/>
                <path opacity="0.5" d="M3 18V21H6V18H3ZM8 14V21H11V14H8Z" fill="currentColor"/>
            </svg>
        </ng-template>
    `,
    imports: [NgClass],
})
export class IconMenuSignalComponent {
    @Input() class: any = '';
    @ViewChild('template', { static: true }) template: any;
    constructor(private viewContainerRef: ViewContainerRef) { }
    ngOnInit() {
        this.viewContainerRef.createEmbeddedView(this.template);
        this.viewContainerRef.element.nativeElement.remove();
    }
}
