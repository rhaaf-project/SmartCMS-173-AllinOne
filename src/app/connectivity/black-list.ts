import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../environments/environment';
import { toggleAnimation } from '../shared/animations';
import { IconPlusComponent } from '../shared/icon/icon-plus';
import { IconPencilComponent } from '../shared/icon/icon-pencil';
import { IconTrashLinesComponent } from '../shared/icon/icon-trash-lines';
import { IconCircleCheckComponent } from '../shared/icon/icon-circle-check';
import Swal from 'sweetalert2';
import { NgScrollbarModule } from 'ngx-scrollbar';

@Component({
    templateUrl: './black-list.html',
    imports: [
        CommonModule,
        FormsModule,
        IconPlusComponent,
        IconPencilComponent,
        IconTrashLinesComponent,
        IconCircleCheckComponent,
        NgScrollbarModule
    ],
    standalone: true,
    animations: [toggleAnimation],
})
export class BlackListComponent implements OnInit {
    blackLists: any[] = [];
    isLoading = false;
    search = '';
    showModal = false;
    modalMode = 'create';

    form: any = {
        id: null,
        number: '',
        description: ''
    };

    constructor(private http: HttpClient) { }

    ngOnInit() {
        this.loadBlackLists();
    }

    loadBlackLists() {
        this.isLoading = true;
        this.http.get<any>(`${environment.apiUrl}/black-lists`).subscribe({
            next: (res: any) => {
                this.blackLists = res.data;
                this.isLoading = false;
            },
            error: () => {
                this.isLoading = false;
                this.showMessage('Failed to load black lists', 'error');
            }
        });
    }

    openModal(mode: string, item: any = null) {
        this.modalMode = mode;
        if (mode === 'edit' && item) {
            this.form = { ...item };
        } else {
            this.form = {
                id: null,
                number: '',
                description: ''
            };
        }
        this.showModal = true;
    }

    closeModal() {
        this.showModal = false;
    }

    saveBlackList() {
        if (!this.form.number) {
            this.showMessage('Number is required', 'error');
            return;
        }

        const data = {
            number: this.form.number,
            description: this.form.description
        };

        if (this.modalMode === 'create') {
            this.http.post(`${environment.apiUrl}/black-lists`, data).subscribe({
                next: () => {
                    this.showMessage('Black list created successfully');
                    this.closeModal();
                    this.loadBlackLists();
                },
                error: (err) => this.showMessage(err.error?.error || 'Failed to create', 'error')
            });
        } else {
            this.http.put(`${environment.apiUrl}/black-lists/${this.form.id}`, data).subscribe({
                next: () => {
                    this.showMessage('Black list updated successfully');
                    this.closeModal();
                    this.loadBlackLists();
                },
                error: (err) => this.showMessage(err.error?.error || 'Failed to update', 'error')
            });
        }
    }

    deleteBlackList(id: number) {
        Swal.fire({
            title: 'Are you sure?',
            text: "You won't be able to revert this!",
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#3085d6',
            cancelButtonColor: '#d33',
            confirmButtonText: 'Yes, delete it!'
        }).then((result) => {
            if (result.isConfirmed) {
                this.http.delete(`${environment.apiUrl}/black-lists/${id}`).subscribe({
                    next: () => {
                        this.showMessage('Deleted successfully');
                        this.loadBlackLists();
                    },
                    error: () => this.showMessage('Failed to delete', 'error')
                });
            }
        });
    }

    showMessage(msg: string, type: 'success' | 'error' = 'success') {
        const toast = Swal.mixin({
            toast: true,
            position: 'top-end',
            showConfirmButton: false,
            timer: 3000,
            customClass: { container: 'toast' },
        });
        toast.fire({
            icon: type,
            title: msg,
            padding: '10px 20px',
        });
    }
}
