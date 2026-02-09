import { Component } from '@angular/core';
import { IconSendComponent } from '../../shared/icon/icon-send';
import { IconPrinterComponent } from '../../shared/icon/icon-printer';
import { IconDownloadComponent } from '../../shared/icon/icon-download';
import { IconPlusComponent } from '../../shared/icon/icon-plus';
import { IconEditComponent } from '../../shared/icon/icon-edit';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';

@Component({
    templateUrl: './preview.html',
    imports: [CommonModule, FormsModule, RouterModule, IconSendComponent, IconPrinterComponent, IconDownloadComponent, IconPlusComponent, IconEditComponent],
})
export class InvoicePreviewComponent {
    constructor() {}
    items = [
        {
            id: 1,
            title: 'Calendar App Customization',
            quantity: 1,
            price: '120',
            amount: '120',
        },
        {
            id: 2,
            title: 'Chat App Customization',
            quantity: 1,
            price: '230',
            amount: '230',
        },
        {
            id: 3,
            title: 'Laravel Integration',
            quantity: 1,
            price: '405',
            amount: '405',
        },
        {
            id: 4,
            title: 'Backend UI Design',
            quantity: 1,
            price: '2500',
            amount: '2500',
        },
    ];
    columns = [
        {
            key: 'id',
            label: 'S.NO',
        },
        {
            key: 'title',
            label: 'ITEMS',
        },
        {
            key: 'quantity',
            label: 'QTY',
        },
        {
            key: 'price',
            label: 'PRICE',
            class: 'ltr:text-right rtl:text-left',
        },
        {
            key: 'amount',
            label: 'AMOUNT',
            class: 'ltr:text-right rtl:text-left',
        },
    ];

    print = () => {
        window.print();
    };
}
