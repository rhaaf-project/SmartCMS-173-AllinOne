import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { toggleAnimation } from '../shared/animations';

import { IconPencilComponent } from '../shared/icon/icon-pencil';
import { IconTrashLinesComponent } from '../shared/icon/icon-trash-lines';
import { IconCopyComponent } from '../shared/icon/icon-copy';
import { IconCircleCheckComponent } from '../shared/icon/icon-circle-check';

@Component({
    templateUrl: './recording.html',
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
export class RecordingComponent implements OnInit {
    search = '';
    showModal = false;
    modalMode: 'create' | 'edit' = 'create';
    isLoading = false;

    // Mock data - Asterisk call recording settings
    items = [
        { id: 1, name: 'All Inbound Calls', record_type: 'inbound', extensions: ['All'], format: 'wav', storage_path: '/var/spool/asterisk/monitor', on_demand: false, is_active: true },
        { id: 2, name: 'Sales Outbound', record_type: 'outbound', extensions: ['201', '202', '203'], format: 'mp3', storage_path: '/var/spool/asterisk/monitor/sales', on_demand: false, is_active: true },
        { id: 3, name: 'Support Calls', record_type: 'both', extensions: ['301', '302', '303'], format: 'wav', storage_path: '/var/spool/asterisk/monitor/support', on_demand: true, is_active: true },
        { id: 4, name: 'Executive Lines', record_type: 'both', extensions: ['100', '101'], format: 'wav', storage_path: '/var/spool/asterisk/monitor/exec', on_demand: true, is_active: false },
    ];

    formData: any = {
        name: '',
        record_type: 'both',
        extensions: '',
        format: 'wav',
        storage_path: '/var/spool/asterisk/monitor',
        on_demand: false,
        is_active: true,
    };

    recordTypes = ['inbound', 'outbound', 'both'];
    formats = ['wav', 'mp3', 'gsm', 'wav49'];

    constructor() { }

    ngOnInit(): void { }

    get filteredItems() {
        if (!this.search) return this.items;
        const s = this.search.toLowerCase();
        return this.items.filter(r =>
            r.name.toLowerCase().includes(s) ||
            r.record_type.toLowerCase().includes(s)
        );
    }

    openCreateModal() {
        this.modalMode = 'create';
        this.formData = { name: '', record_type: 'both', extensions: '', format: 'wav', storage_path: '/var/spool/asterisk/monitor', on_demand: false, is_active: true };
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
        if (confirm('Are you sure you want to delete this recording rule?')) {
            this.items = this.items.filter(r => r.id !== id);
        }
    }

    copyRecord(item: any) {
        this.modalMode = 'create';
        this.formData = { ...item, id: null, name: item.name + ' (copy)', extensions: Array.isArray(item.extensions) ? item.extensions.join(', ') : item.extensions };
        this.showModal = true;
    }

    getTypeClass(type: string): string {
        switch (type) {
            case 'inbound': return 'badge bg-info';
            case 'outbound': return 'badge bg-warning';
            case 'both': return 'badge bg-success';
            default: return 'badge bg-dark';
        }
    }
}
