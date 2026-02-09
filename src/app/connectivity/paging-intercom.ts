import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { toggleAnimation } from '../shared/animations';

import { IconPencilComponent } from '../shared/icon/icon-pencil';
import { IconTrashLinesComponent } from '../shared/icon/icon-trash-lines';
import { IconCopyComponent } from '../shared/icon/icon-copy';
import { IconCircleCheckComponent } from '../shared/icon/icon-circle-check';

@Component({
    templateUrl: './paging-intercom.html',
    imports: [
        CommonModule,
        FormsModule,
        IconPencilComponent,
        IconTrashLinesComponent,
        IconCopyComponent,
        IconCircleCheckComponent,
    ],
    animations: [toggleAnimation],
})
export class PagingIntercomComponent implements OnInit {
    search = '';
    showModal = false;
    modalMode: 'create' | 'edit' = 'create';
    isLoading = false;

    // Mock data - Asterisk Paging/Intercom groups
    items = [
        { id: 1, name: 'All Phones Page', extension: '*80', description: 'Page all extensions', members: ['101', '102', '103', '104', '105'], duplex: 'no', busy_tone: 'no', is_active: true },
        { id: 2, name: 'Floor 1 Intercom', extension: '*81', description: 'Intercom Floor 1', members: ['110', '111', '112'], duplex: 'yes', busy_tone: 'yes', is_active: true },
        { id: 3, name: 'Sales Team Page', extension: '*82', description: 'Page sales department', members: ['201', '202', '203'], duplex: 'no', busy_tone: 'no', is_active: true },
        { id: 4, name: 'Warehouse Intercom', extension: '*83', description: 'Warehouse paging', members: ['301', '302'], duplex: 'yes', busy_tone: 'yes', is_active: false },
    ];

    formData: any = {
        name: '',
        extension: '',
        description: '',
        members: '',
        duplex: 'no',
        busy_tone: 'no',
        is_active: true,
    };

    duplexOptions = ['yes', 'no'];

    constructor() { }

    ngOnInit(): void { }

    get filteredItems() {
        if (!this.search) return this.items;
        const s = this.search.toLowerCase();
        return this.items.filter(r =>
            r.name.toLowerCase().includes(s) ||
            r.extension.toLowerCase().includes(s)
        );
    }

    openCreateModal() {
        this.modalMode = 'create';
        this.formData = { name: '', extension: '', description: '', members: '', duplex: 'no', busy_tone: 'no', is_active: true };
        this.showModal = true;
    }

    openEditModal(item: any) {
        this.modalMode = 'edit';
        this.formData = { ...item, members: Array.isArray(item.members) ? item.members.join(', ') : item.members };
        this.showModal = true;
    }

    closeModal() {
        this.showModal = false;
    }

    handleSubmit() {
        const data = { ...this.formData, members: this.formData.members.split(',').map((e: string) => e.trim()) };
        if (this.modalMode === 'create') {
            this.items.push({ ...data, id: Date.now() });
        } else {
            const idx = this.items.findIndex(r => r.id === this.formData.id);
            if (idx !== -1) this.items[idx] = data;
        }
        this.closeModal();
    }

    deleteItem(id: number) {
        if (confirm('Are you sure you want to delete this paging group?')) {
            this.items = this.items.filter(r => r.id !== id);
        }
    }

    copyRecord(item: any) {
        this.modalMode = 'create';
        this.formData = { ...item, id: null, name: item.name + ' (copy)', members: Array.isArray(item.members) ? item.members.join(', ') : item.members };
        this.showModal = true;
    }
}
