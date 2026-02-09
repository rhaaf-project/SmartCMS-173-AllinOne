import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { toggleAnimation } from '../shared/animations';

import { IconPencilComponent } from '../shared/icon/icon-pencil';
import { IconTrashLinesComponent } from '../shared/icon/icon-trash-lines';
import { IconCopyComponent } from '../shared/icon/icon-copy';
import { IconCircleCheckComponent } from '../shared/icon/icon-circle-check';

@Component({
    templateUrl: './ring-group.html',
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
export class RingGroupComponent implements OnInit {
    search = '';
    showModal = false;
    modalMode: 'create' | 'edit' = 'create';
    isLoading = false;

    // Mock data - Asterisk Ring Groups
    items = [
        { id: 1, name: 'Sales Team', extension: '600', description: 'Sales department ring group', strategy: 'ringall', ring_time: 20, members: ['201', '202', '203'], failover_destination: 'voicemail-sales', is_active: true },
        { id: 2, name: 'Support Queue', extension: '601', description: 'Technical support', strategy: 'hunt', ring_time: 15, members: ['301', '302', '303', '304'], failover_destination: 'voicemail-support', is_active: true },
        { id: 3, name: 'Reception', extension: '602', description: 'Front desk', strategy: 'ringall', ring_time: 25, members: ['100', '101'], failover_destination: 'ivr-main', is_active: true },
        { id: 4, name: 'After Hours', extension: '603', description: 'After hours team', strategy: 'memoryhunt', ring_time: 30, members: ['401', '402'], failover_destination: 'voicemail-general', is_active: false },
    ];

    formData: any = {
        name: '',
        extension: '',
        description: '',
        strategy: 'ringall',
        ring_time: 20,
        members: '',
        failover_destination: '',
        is_active: true,
    };

    strategies = [
        { value: 'ringall', label: 'Ring All' },
        { value: 'hunt', label: 'Hunt (Linear)' },
        { value: 'memoryhunt', label: 'Memory Hunt' },
        { value: 'firstunavailable', label: 'First Unavailable' },
        { value: 'random', label: 'Random' },
    ];

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
        this.formData = { name: '', extension: '', description: '', strategy: 'ringall', ring_time: 20, members: '', failover_destination: '', is_active: true };
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
        if (confirm('Are you sure you want to delete this ring group?')) {
            this.items = this.items.filter(r => r.id !== id);
        }
    }

    copyRecord(item: any) {
        this.modalMode = 'create';
        this.formData = { ...item, id: null, name: item.name + ' (copy)', members: Array.isArray(item.members) ? item.members.join(', ') : item.members };
        this.showModal = true;
    }

    getStrategyLabel(value: string): string {
        const s = this.strategies.find(st => st.value === value);
        return s ? s.label : value;
    }
}
