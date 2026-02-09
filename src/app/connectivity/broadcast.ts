import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { toggleAnimation } from '../shared/animations';

import { IconPencilComponent } from '../shared/icon/icon-pencil';
import { IconTrashLinesComponent } from '../shared/icon/icon-trash-lines';
import { IconCopyComponent } from '../shared/icon/icon-copy';
import { IconCircleCheckComponent } from '../shared/icon/icon-circle-check';

@Component({
    templateUrl: './broadcast.html',
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
export class BroadcastComponent implements OnInit {
    search = '';
    showModal = false;
    modalMode: 'create' | 'edit' = 'create';
    isLoading = false;

    // Mock data - Asterisk Broadcast/Page groups
    items = [
        { id: 1, name: 'Morning Announcement', extension: '*30', description: 'Daily morning broadcast', audio_file: 'morning_message.wav', extensions: ['101', '102', '103', '104', '105'], retry_count: 2, is_active: true },
        { id: 2, name: 'Emergency Alert', extension: '*31', description: 'Emergency broadcast to all', audio_file: 'emergency.wav', extensions: ['All'], retry_count: 3, is_active: true },
        { id: 3, name: 'Floor 1 Announcement', extension: '*32', description: 'Broadcast to Floor 1', audio_file: 'custom.wav', extensions: ['110', '111', '112'], retry_count: 1, is_active: false },
    ];

    formData: any = {
        name: '',
        extension: '',
        description: '',
        audio_file: '',
        extensions: '',
        retry_count: 2,
        is_active: true,
    };

    constructor() { }

    ngOnInit(): void { }

    get filteredItems() {
        if (!this.search) return this.items;
        const s = this.search.toLowerCase();
        return this.items.filter(r =>
            r.name.toLowerCase().includes(s) ||
            r.extension.toLowerCase().includes(s) ||
            r.description.toLowerCase().includes(s)
        );
    }

    openCreateModal() {
        this.modalMode = 'create';
        this.formData = { name: '', extension: '', description: '', audio_file: '', extensions: '', retry_count: 2, is_active: true };
        this.showModal = true;
    }

    openEditModal(item: any) {
        this.modalMode = 'edit';
        this.formData = { ...item, extensions: Array.isArray(item.extensions) ? item.extensions.join(', ') : item.extensions };
        this.showModal = true;
    }

    closeModal() {
        this.showModal = false;
    }

    handleSubmit() {
        const data = { ...this.formData, extensions: this.formData.extensions.split(',').map((e: string) => e.trim()) };
        if (this.modalMode === 'create') {
            this.items.push({ ...data, id: Date.now() });
        } else {
            const idx = this.items.findIndex(r => r.id === this.formData.id);
            if (idx !== -1) this.items[idx] = data;
        }
        this.closeModal();
    }

    deleteItem(id: number) {
        if (confirm('Are you sure you want to delete this broadcast?')) {
            this.items = this.items.filter(r => r.id !== id);
        }
    }

    copyRecord(item: any) {
        this.modalMode = 'create';
        this.formData = { ...item, id: null, name: item.name + ' (copy)', extensions: Array.isArray(item.extensions) ? item.extensions.join(', ') : item.extensions };
        this.showModal = true;
    }
}
