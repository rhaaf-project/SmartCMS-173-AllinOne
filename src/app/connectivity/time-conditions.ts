import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { toggleAnimation } from '../shared/animations';

import { IconPencilComponent } from '../shared/icon/icon-pencil';
import { IconTrashLinesComponent } from '../shared/icon/icon-trash-lines';
import { IconCopyComponent } from '../shared/icon/icon-copy';
import { IconCircleCheckComponent } from '../shared/icon/icon-circle-check';

@Component({
    templateUrl: './time-conditions.html',
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
export class TimeConditionsComponent implements OnInit {
    search = '';
    showModal = false;
    modalMode: 'create' | 'edit' = 'create';
    isLoading = false;

    // Mock data - Asterisk Time Conditions (GotoIfTime)
    items = [
        { id: 1, name: 'Business Hours', time_start: '09:00', time_end: '17:00', days: ['mon', 'tue', 'wed', 'thu', 'fri'], match_destination: 'ivr-main', no_match_destination: 'voicemail-afterhours', is_active: true },
        { id: 2, name: 'Weekend Hours', time_start: '10:00', time_end: '14:00', days: ['sat', 'sun'], match_destination: 'ring-group-weekend', no_match_destination: 'voicemail-general', is_active: true },
        { id: 3, name: 'Holiday Mode', time_start: '00:00', time_end: '23:59', days: ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'], match_destination: 'announcement-holiday', no_match_destination: 'voicemail-general', is_active: false },
        { id: 4, name: 'Lunch Break', time_start: '12:00', time_end: '13:00', days: ['mon', 'tue', 'wed', 'thu', 'fri'], match_destination: 'moh-lunch', no_match_destination: 'ivr-main', is_active: true },
    ];

    formData: any = {
        name: '',
        time_start: '09:00',
        time_end: '17:00',
        days: [],
        match_destination: '',
        no_match_destination: '',
        is_active: true,
    };

    allDays = [
        { value: 'mon', label: 'Monday' },
        { value: 'tue', label: 'Tuesday' },
        { value: 'wed', label: 'Wednesday' },
        { value: 'thu', label: 'Thursday' },
        { value: 'fri', label: 'Friday' },
        { value: 'sat', label: 'Saturday' },
        { value: 'sun', label: 'Sunday' },
    ];

    constructor() { }

    ngOnInit(): void { }

    get filteredItems() {
        if (!this.search) return this.items;
        const s = this.search.toLowerCase();
        return this.items.filter(r =>
            r.name.toLowerCase().includes(s) ||
            r.match_destination.toLowerCase().includes(s)
        );
    }

    openCreateModal() {
        this.modalMode = 'create';
        this.formData = { name: '', time_start: '09:00', time_end: '17:00', days: [], match_destination: '', no_match_destination: '', is_active: true };
        this.showModal = true;
    }

    openEditModal(item: any) {
        this.modalMode = 'edit';
        this.formData = { ...item, days: [...item.days] };
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
        if (confirm('Are you sure you want to delete this time condition?')) {
            this.items = this.items.filter(r => r.id !== id);
        }
    }

    copyRecord(item: any) {
        this.modalMode = 'create';
        this.formData = { ...item, id: null, name: item.name + ' (copy)', days: [...item.days] };
        this.showModal = true;
    }

    toggleDay(day: string) {
        const idx = this.formData.days.indexOf(day);
        if (idx === -1) {
            this.formData.days.push(day);
        } else {
            this.formData.days.splice(idx, 1);
        }
    }

    getDayLabels(days: string[]): string {
        if (days.length === 7) return 'Every day';
        if (days.length === 5 && !days.includes('sat') && !days.includes('sun')) return 'Weekdays';
        if (days.length === 2 && days.includes('sat') && days.includes('sun')) return 'Weekends';
        return days.map(d => d.charAt(0).toUpperCase() + d.slice(1, 3)).join(', ');
    }
}
