import { NgClass } from '@angular/common';
import { Component, Input, ViewChild, ViewContainerRef } from '@angular/core';
@Component({
    selector: 'icon-menu-building',
    template: `
        <ng-template #template>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" [ngClass]="class">
                <path opacity="0.5" d="M4 22V4C4 2.89543 4.89543 2 6 2H18C19.1046 2 20 2.89543 20 4V22H4Z" fill="currentColor"/>
                <path d="M7 6H9V8H7V6Z" fill="currentColor"/>
                <path d="M11 6H13V8H11V6Z" fill="currentColor"/>
                <path d="M15 6H17V8H15V6Z" fill="currentColor"/>
                <path d="M7 10H9V12H7V10Z" fill="currentColor"/>
                <path d="M11 10H13V12H11V10Z" fill="currentColor"/>
                <path d="M15 10H17V12H15V10Z" fill="currentColor"/>
                <path d="M7 14H9V16H7V14Z" fill="currentColor"/>
                <path d="M11 14H13V16H11V14Z" fill="currentColor"/>
                <path d="M15 14H17V16H15V14Z" fill="currentColor"/>
                <path d="M10 18H14V22H10V18Z" fill="currentColor"/>
            </svg>
        </ng-template>
    `,
    imports: [NgClass],
})
export class IconMenuBuildingComponent {
    @Input() class: any = '';
    @ViewChild('template', { static: true }) template: any;
    constructor(private viewContainerRef: ViewContainerRef) { }
    ngOnInit() {
        this.viewContainerRef.createEmbeddedView(this.template);
        this.viewContainerRef.element.nativeElement.remove();
    }
}
