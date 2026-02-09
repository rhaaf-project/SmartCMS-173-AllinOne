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
    templateUrl: './custom-destination.html',
    imports: [CommonModule, FormsModule, IconPlusComponent, IconPencilComponent, IconTrashLinesComponent, NgScrollbarModule],
    standalone: true,
    animations: [toggleAnimation],
})
export class CustomDestinationComponent implements OnInit {
    items: any[] = [];
    isLoading = false;
    search = '';
    showModal = false;
    modalMode = 'create';

    form: any = this.getEmptyForm();

    constructor(private http: HttpClient) { }

    ngOnInit() { this.loadItems(); }

    getEmptyForm() {
        return { id: null, target: '', description: '', notes: '', return_call: 0 };
    }

    loadItems() {
        this.isLoading = true;
        this.http.get<any>(`${environment.apiUrl}/custom-destinations`).subscribe({
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
        if (!this.form.target) { this.showMessage('Target is required', 'error'); return; }
        const url = this.modalMode === 'create' ? `${environment.apiUrl}/custom-destinations` : `${environment.apiUrl}/custom-destinations/${this.form.id}`;
        const req = this.modalMode === 'create' ? this.http.post(url, this.form) : this.http.put(url, this.form);
        req.subscribe({
            next: () => { this.showMessage('Saved successfully'); this.closeModal(); this.loadItems(); },
            error: (err) => this.showMessage(err.error?.error || 'Failed to save', 'error')
        });
    }

    delete(id: number) {
        Swal.fire({ title: 'Are you sure?', text: "You won't be able to revert this!", icon: 'warning', showCancelButton: true, confirmButtonText: 'Yes, delete it!' })
            .then((result) => {
                if (result.isConfirmed) {
                    this.http.delete(`${environment.apiUrl}/custom-destinations/${id}`).subscribe({
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
