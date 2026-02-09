import { Component } from '@angular/core';
import { Router, RouterModule } from '@angular/router';
import { Store } from '@ngrx/store';
import { TranslatePipe, TranslateService } from '@ngx-translate/core';
import { slideDownUp } from '../shared/animations';
import { NgClass } from '@angular/common';
import { IconCaretsDownComponent } from '../shared/icon/icon-carets-down';
import { NgScrollbarModule } from 'ngx-scrollbar';
import { IconMenuDashboardComponent } from '../shared/icon/menu/icon-menu-dashboard';
import { IconCaretDownComponent } from '../shared/icon/icon-caret-down';
import { IconMinusComponent } from '../shared/icon/icon-minus';
import { IconMenuChatComponent } from '../shared/icon/menu/icon-menu-chat';
import { IconMenuMailboxComponent } from '../shared/icon/menu/icon-menu-mailbox';
import { IconMenuTodoComponent } from '../shared/icon/menu/icon-menu-todo';
import { IconMenuNotesComponent } from '../shared/icon/menu/icon-menu-notes';
import { IconMenuScrumboardComponent } from '../shared/icon/menu/icon-menu-scrumboard';
import { IconMenuContactsComponent } from '../shared/icon/menu/icon-menu-contacts';
import { IconMenuInvoiceComponent } from '../shared/icon/menu/icon-menu-invoice';
import { IconMenuCalendarComponent } from '../shared/icon/menu/icon-menu-calendar';
import { IconMenuComponentsComponent } from '../shared/icon/menu/icon-menu-components';
import { IconMenuElementsComponent } from '../shared/icon/menu/icon-menu-elements';
import { IconMenuChartsComponent } from '../shared/icon/menu/icon-menu-charts';
import { IconMenuWidgetsComponent } from '../shared/icon/menu/icon-menu-widgets';
import { IconMenuFontIconsComponent } from '../shared/icon/menu/icon-menu-font-icons';
import { IconMenuDragAndDropComponent } from '../shared/icon/menu/icon-menu-drag-and-drop';
import { IconMenuTablesComponent } from '../shared/icon/menu/icon-menu-tables';
import { IconMenuDatatablesComponent } from '../shared/icon/menu/icon-menu-datatables';
import { IconMenuFormsComponent } from '../shared/icon/menu/icon-menu-forms';
import { IconMenuUsersComponent } from '../shared/icon/menu/icon-menu-users';
import { IconMenuPagesComponent } from '../shared/icon/menu/icon-menu-pages';
import { IconMenuAuthenticationComponent } from '../shared/icon/menu/icon-menu-authentication';
import { IconMenuDocumentationComponent } from '../shared/icon/menu/icon-menu-documentation';
import { IconMenuBuildingComponent } from '../shared/icon/menu/icon-menu-building';
import { IconMenuSignalComponent } from '../shared/icon/menu/icon-menu-signal';
import { IconMenuShieldComponent } from '../shared/icon/menu/icon-menu-shield';
import { IconMenuServerComponent } from '../shared/icon/menu/icon-menu-server';
import { IconMenuMicrophoneComponent } from '../shared/icon/menu/icon-menu-microphone';
import { IconMenuPhoneComponent } from '../shared/icon/menu/icon-menu-phone';
import { IconMenuGlobeComponent } from '../shared/icon/menu/icon-menu-globe';
import { IconMenuDownloadComponent } from '../shared/icon/menu/icon-menu-download';
import { IconMenuDocumentComponent } from '../shared/icon/menu/icon-menu-document';
import { IconMenuUserGroupComponent } from '../shared/icon/menu/icon-menu-user-group';

@Component({
    selector: 'sidebar',
    templateUrl: './sidebar.html',
    imports: [
        NgClass,
        TranslatePipe,
        NgScrollbarModule,
        RouterModule,
        IconCaretsDownComponent,
        IconMenuDashboardComponent,
        IconCaretDownComponent,
        IconMinusComponent,
        IconMenuChatComponent,
        IconMenuMailboxComponent,
        IconMenuTodoComponent,
        IconMenuNotesComponent,
        IconMenuScrumboardComponent,
        IconMenuContactsComponent,
        IconMenuInvoiceComponent,
        IconMenuCalendarComponent,
        IconMenuComponentsComponent,
        IconMenuElementsComponent,
        IconMenuChartsComponent,
        IconMenuWidgetsComponent,
        IconMenuFontIconsComponent,
        IconMenuDragAndDropComponent,
        IconMenuTablesComponent,
        IconMenuDatatablesComponent,
        IconMenuFormsComponent,
        IconMenuUsersComponent,
        IconMenuPagesComponent,
        IconMenuAuthenticationComponent,
        IconMenuDocumentationComponent,
        IconMenuBuildingComponent,
        IconMenuSignalComponent,
        IconMenuShieldComponent,
        IconMenuServerComponent,
        IconMenuMicrophoneComponent,
        IconMenuPhoneComponent,
        IconMenuGlobeComponent,
        IconMenuDownloadComponent,
        IconMenuDocumentComponent,
        IconMenuUserGroupComponent,
    ],
    animations: [slideDownUp],
})
export class SidebarComponent {
    active = false;
    store: any;
    activeDropdown: string[] = [];
    parentDropdown: string = '';
    constructor(
        public translate: TranslateService,
        public storeData: Store<any>,
        public router: Router,
    ) {
        this.initStore();
    }
    async initStore() {
        this.storeData
            .select((d) => d.index)
            .subscribe((d) => {
                this.store = d;
            });
    }

    ngOnInit() {
        this.setActiveDropdown();
    }

    setActiveDropdown() {
        const selector = document.querySelector('.sidebar ul a[routerLink="' + window.location.pathname + '"]');
        if (selector) {
            selector.classList.add('active');
            const ul: any = selector.closest('ul.sub-menu');
            if (ul) {
                let ele: any = ul.closest('li.menu').querySelectorAll('.nav-link') || [];
                if (ele.length) {
                    ele = ele[0];
                    setTimeout(() => {
                        ele.click();
                    });
                }
            }
        }
    }

    toggleMobileMenu() {
        if (window.innerWidth < 1024) {
            this.storeData.dispatch({ type: 'toggleSidebar' });
        }
    }

    toggleAccordion(name: string, parent?: string) {
        if (this.activeDropdown.includes(name)) {
            this.activeDropdown = this.activeDropdown.filter((d) => d !== name);
        } else {
            this.activeDropdown.push(name);
        }
    }
}
