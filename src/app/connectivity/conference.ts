import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../environments/environment';
import { toggleAnimation } from '../shared/animations';
import { IconPlusComponent } from '../shared/icon/icon-plus';
import { IconPencilComponent } from '../shared/icon/icon-pencil';
import { IconTrashLinesComponent } from '../shared/icon/icon-trash-lines';
import Swal from 'sweetalert2';
import { NgScrollbarModule } from 'ngx-scrollbar';

@Component({
    templateUrl: './conference.html',
    imports: [CommonModule, FormsModule, IconPlusComponent, IconPencilComponent, IconTrashLinesComponent, NgScrollbarModule],
    standalone: true,
    animations: [toggleAnimation],
})
export class ConferenceComponent implements OnInit {
    items: any[] = [];
    isLoading = false;
    search = '';
    showModal = false;
    modalMode = 'create';

    form: any = this.getEmptyForm();

    constructor(private http: HttpClient) { }

    ngOnInit() {
        this.loadItems();
    }

    getEmptyForm() {
        return {
            id: null,
            conference_number: '',
            conference_name: '',
            user_pin: '',
            admin_pin: '',
            language: 'Inherit',
            join_message: 'None',
            leader_wait: 1,
            leader_leave: 1,
            talker_optimization: 1,
            talker_detection: 1,
            quiet_mode: 0,
            user_count: 1,
            user_join_leave: 1,
            music_on_hold: 1,
            music_on_hold_class: 'Inherit',
            allow_menu: 1,
            record_conference: 0,
            max_participants: 0,
            mute_on_join: 0,
            member_timeout: 21600
        };
    }

    loadItems() {
        this.isLoading = true;
        this.http.get<any>(`${environment.apiUrl}/conferences`).subscribe({
            next: (res) => { this.items = res.data; this.isLoading = false; },
            error: () => { this.isLoading = false; this.showMessage('Failed to load', 'error'); }
        });
    }

    openModal(mode: string, item: any = null) {
        this.modalMode = mode;
        this.form = mode === 'edit' && item ? { ...item } : this.getEmptyForm();
        this.showModal = true;
    }

    closeModal() { this.showModal = false; }

    save() {
        if (!this.form.conference_number || !this.form.conference_name) {
            this.showMessage('Conference Number and Name are required', 'error');
            return;
        }
        const url = this.modalMode === 'create'
            ? `${environment.apiUrl}/conferences`
            : `${environment.apiUrl}/conferences/${this.form.id}`;
        const req = this.modalMode === 'create'
            ? this.http.post(url, this.form)
            : this.http.put(url, this.form);
        req.subscribe({
            next: () => { this.showMessage('Saved successfully'); this.closeModal(); this.loadItems(); },
            error: (err) => this.showMessage(err.error?.error || 'Failed to save', 'error')
        });
    }

    delete(id: number) {
        Swal.fire({ title: 'Are you sure?', text: "You won't be able to revert this!", icon: 'warning', showCancelButton: true, confirmButtonText: 'Yes, delete it!' })
            .then((result) => {
                if (result.isConfirmed) {
                    this.http.delete(`${environment.apiUrl}/conferences/${id}`).subscribe({
                        next: () => { this.showMessage('Deleted'); this.loadItems(); },
                        error: () => this.showMessage('Failed to delete', 'error')
                    });
                }
            });
    }

    showMessage(msg: string, type: 'success' | 'error' = 'success') {
        Swal.mixin({ toast: true, position: 'top-end', showConfirmButton: false, timer: 3000 }).fire({ icon: type, title: msg });
    }
}
