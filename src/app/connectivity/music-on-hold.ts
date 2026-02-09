import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { toggleAnimation } from '../shared/animations';

import { IconPencilComponent } from '../shared/icon/icon-pencil';
import { IconTrashLinesComponent } from '../shared/icon/icon-trash-lines';
import { IconCopyComponent } from '../shared/icon/icon-copy';
import { IconCircleCheckComponent } from '../shared/icon/icon-circle-check';

@Component({
    templateUrl: './music-on-hold.html',
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
export class MusicOnHoldComponent implements OnInit {
    search = '';
    showModal = false;
    modalMode: 'create' | 'edit' = 'create';
    isLoading = false;

    // Mock data - Asterisk Music on Hold classes
    items = [
        { id: 1, name: 'default', mode: 'files', directory: '/var/lib/asterisk/moh', sort: 'random', format: 'wav', is_active: true },
        { id: 2, name: 'jazz', mode: 'files', directory: '/var/lib/asterisk/moh/jazz', sort: 'alpha', format: 'mp3', is_active: true },
        { id: 3, name: 'classical', mode: 'files', directory: '/var/lib/asterisk/moh/classical', sort: 'random', format: 'wav', is_active: true },
        { id: 4, name: 'queue-music', mode: 'files', directory: '/var/lib/asterisk/moh/queue', sort: 'alpha', format: 'wav', is_active: false },
    ];

    formData: any = {
        name: '',
        mode: 'files',
        directory: '/var/lib/asterisk/moh',
        sort: 'random',
        format: 'wav',
        is_active: true,
    };

    modes = ['files', 'custom', 'mp3', 'quietmp3'];
    sortOptions = ['random', 'alpha', 'random_start'];
    formats = ['wav', 'mp3', 'gsm', 'ulaw', 'alaw'];

    constructor() { }

    ngOnInit(): void { }

    get filteredItems() {
        if (!this.search) return this.items;
        const s = this.search.toLowerCase();
        return this.items.filter(r =>
            r.name.toLowerCase().includes(s) ||
            r.directory.toLowerCase().includes(s)
        );
    }

    openCreateModal() {
        this.modalMode = 'create';
        this.formData = { name: '', mode: 'files', directory: '/var/lib/asterisk/moh', sort: 'random', format: 'wav', is_active: true };
        this.showModal = true;
    }

    openEditModal(item: any) {
        this.modalMode = 'edit';
        this.formData = { ...item };
        this.showModal = true;
    }

    closeModal() {
        this.showModal = false;
    }

    handleSubmit() {
        if (this.modalMode === 'create') {
            this.items.push({ ...this.formData, id: Date.now() });
        } else {
            const idx = this.items.findIndex(r => r.id === this.formData.id);
            if (idx !== -1) this.items[idx] = { ...this.formData };
        }
        this.closeModal();
    }

    deleteItem(id: number) {
        if (confirm('Are you sure you want to delete this Music on Hold class?')) {
            this.items = this.items.filter(r => r.id !== id);
        }
    }

    copyRecord(item: any) {
        this.modalMode = 'create';
        this.formData = { ...item, id: null, name: item.name + '-copy' };
        this.showModal = true;
    }
}
