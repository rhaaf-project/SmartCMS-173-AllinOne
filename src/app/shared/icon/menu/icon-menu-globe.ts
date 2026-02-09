import { NgClass } from '@angular/common';
import { Component, Input, ViewChild, ViewContainerRef } from '@angular/core';
@Component({
    selector: 'icon-menu-globe',
    template: `
        <ng-template #template>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" [ngClass]="class">
                <circle opacity="0.5" cx="12" cy="12" r="10" fill="currentColor"/>
                <path d="M12 2C12 2 8 6 8 12C8 18 12 22 12 22" stroke="currentColor" stroke-width="1.5"/>
                <path d="M12 2C12 2 16 6 16 12C16 18 12 22 12 22" stroke="currentColor" stroke-width="1.5"/>
                <path d="M2 12H22" stroke="currentColor" stroke-width="1.5"/>
                <path d="M4 7H20" stroke="currentColor" stroke-width="1.5"/>
                <path d="M4 17H20" stroke="currentColor" stroke-width="1.5"/>
            </svg>
        </ng-template>
    `,
    imports: [NgClass],
})
export class IconMenuGlobeComponent {
    @Input() class: any = '';
    @ViewChild('template', { static: true }) template: any;
    constructor(private viewContainerRef: ViewContainerRef) { }
    ngOnInit() {
        this.viewContainerRef.createEmbeddedView(this.template);
        this.viewContainerRef.element.nativeElement.remove();
    }
}
