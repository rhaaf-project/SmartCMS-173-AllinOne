import { Component, ViewChild } from '@angular/core';
import Swal from 'sweetalert2';
import { NgxCustomModalComponent } from 'ngx-custom-modal';
import { FormBuilder, FormGroup, FormsModule, ReactiveFormsModule, Validators } from '@angular/forms';
import { toggleAnimation } from '../shared/animations';
import { CommonModule } from '@angular/common';
import { IconUserPlusComponent } from '../shared/icon/icon-user-plus';
import { IconListCheckComponent } from '../shared/icon/icon-list-check';
import { IconLayoutGridComponent } from '../shared/icon/icon-layout-grid';
import { IconSearchComponent } from '../shared/icon/icon-search';
import { IconUserComponent } from '../shared/icon/icon-user';
import { IconFacebookComponent } from '../shared/icon/icon-facebook';
import { IconInstagramComponent } from '../shared/icon/icon-instagram';
import { IconLinkedinComponent } from '../shared/icon/icon-linkedin';
import { IconTwitterComponent } from '../shared/icon/icon-twitter';

@Component({
    templateUrl: './contacts.html',
    animations: [toggleAnimation],
    imports: [
        CommonModule,
        FormsModule,
        ReactiveFormsModule,
        IconUserPlusComponent,
        IconListCheckComponent,
        IconLayoutGridComponent,
        IconSearchComponent,
        IconUserComponent,
        IconFacebookComponent,
        IconInstagramComponent,
        IconLinkedinComponent,
        IconTwitterComponent,
        NgxCustomModalComponent,
    ],
})
export class ContactsComponent {
    constructor(public fb: FormBuilder) {}
    displayType = 'list';
    @ViewChild('addContactModal') addContactModal!: NgxCustomModalComponent;
    params!: FormGroup;
    filterdContactsList: any = [];
    searchUser = '';
    contactList = [
        {
            id: 1,
            path: 'profile-35.png',
            name: 'Alan Green',
            role: 'Web Developer',
            email: 'alan@mail.com',
            location: 'Boston, USA',
            phone: '+1 202 555 0197',
            posts: 25,
            followers: '5K',
            following: 500,
        },
        {
            id: 2,
            path: 'profile-35.png',
            name: 'Linda Nelson',
            role: 'Web Designer',
            email: 'linda@mail.com',
            location: 'Sydney, Australia',
            phone: '+1 202 555 0170',
            posts: 25,
            followers: '21.5K',
            following: 350,
        },
        {
            id: 3,
            path: 'profile-35.png',
            name: 'Lila Perry',
            role: 'UX/UI Designer',
            email: 'lila@mail.com',
            location: 'Miami, USA',
            phone: '+1 202 555 0105',
            posts: 20,
            followers: '21.5K',
            following: 350,
        },
        {
            id: 4,
            path: 'profile-35.png',
            name: 'Andy King',
            role: 'Project Lead',
            email: 'andy@mail.com',
            location: 'Tokyo, Japan',
            phone: '+1 202 555 0194',
            posts: 25,
            followers: '21.5K',
            following: 300,
        },
        {
            id: 5,
            path: 'profile-35.png',
            name: 'Jesse Cory',
            role: 'Web Developer',
            email: 'jesse@mail.com',
            location: 'Edinburgh, UK',
            phone: '+1 202 555 0161',
            posts: 30,
            followers: '20K',
            following: 350,
        },
        {
            id: 6,
            path: 'profile-35.png',
            name: 'Xavier',
            role: 'UX/UI Designer',
            email: 'xavier@mail.com',
            location: 'New York, USA',
            phone: '+1 202 555 0155',
            posts: 25,
            followers: '21.5K',
            following: 350,
        },
        {
            id: 7,
            path: 'profile-35.png',
            name: 'Susan',
            role: 'Project Manager',
            email: 'susan@mail.com',
            location: 'Miami, USA',
            phone: '+1 202 555 0118',
            posts: 40,
            followers: '21.5K',
            following: 350,
        },
        {
            id: 8,
            path: 'profile-35.png',
            name: 'Raci Lopez',
            role: 'Web Developer',
            email: 'traci@mail.com',
            location: 'Edinburgh, UK',
            phone: '+1 202 555 0135',
            posts: 25,
            followers: '21.5K',
            following: 350,
        },
        {
            id: 9,
            path: 'profile-35.png',
            name: 'Steven Mendoza',
            role: 'HR',
            email: 'sokol@verizon.net',
            location: 'Monrovia, US',
            phone: '+1 202 555 0100',
            posts: 40,
            followers: '21.8K',
            following: 300,
        },
        {
            id: 10,
            path: 'profile-35.png',
            name: 'James Cantrell',
            role: 'Web Developer',
            email: 'sravani@comcast.net',
            location: 'Michigan, US',
            phone: '+1 202 555 0134',
            posts: 100,
            followers: '28K',
            following: 520,
        },
        {
            id: 11,
            path: 'profile-35.png',
            name: 'Reginald Brown',
            role: 'Web Designer',
            email: 'drhyde@gmail.com',
            location: 'Entrimo, Spain',
            phone: '+1 202 555 0153',
            posts: 35,
            followers: '25K',
            following: 500,
        },
        {
            id: 12,
            path: 'profile-35.png',
            name: 'Stacey Smith',
            role: 'Chief technology officer',
            email: 'maikelnai@optonline.net',
            location: 'Lublin, Poland',
            phone: '+1 202 555 0115',
            posts: 21,
            followers: '5K',
            following: 200,
        },
    ];

    initForm() {
        this.params = this.fb.group({
            id: [0],
            name: ['', Validators.required],
            email: ['', Validators.compose([Validators.required, Validators.email])],
            role: ['', Validators.required],
            phone: ['', Validators.required],
            location: [''],
        });
    }

    ngOnInit() {
        this.searchContacts();
    }

    searchContacts() {
        this.filterdContactsList = this.contactList.filter((d) => d.name.toLowerCase().includes(this.searchUser.toLowerCase()));
    }

    editUser(user: any = null) {
        this.addContactModal.open();
        this.initForm();
        if (user) {
            this.params.setValue({
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role,
                phone: user.phone,
                location: user.location,
            });
        }
    }

    saveUser() {
        if (this.params.controls['name'].errors) {
            this.showMessage('Name is required.', 'error');
            return;
        }
        if (this.params.controls['email'].errors) {
            this.showMessage('Email is required.', 'error');
            return;
        }
        if (this.params.controls['phone'].errors) {
            this.showMessage('Phone is required.', 'error');
            return;
        }
        if (this.params.controls['role'].errors) {
            this.showMessage('Occupation is required.', 'error');
            return;
        }

        if (this.params.value.id) {
            //update user
            let user: any = this.contactList.find((d) => d.id === this.params.value.id);
            user.name = this.params.value.name;
            user.email = this.params.value.email;
            user.role = this.params.value.role;
            user.phone = this.params.value.phone;
            user.location = this.params.value.location;
        } else {
            //add user
            let maxUserId = this.contactList.length
                ? this.contactList.reduce((max, character) => (character.id > max ? character.id : max), this.contactList[0].id)
                : 0;

            let user = {
                id: maxUserId + 1,
                path: 'profile-35.png',
                name: this.params.value.name,
                email: this.params.value.email,
                role: this.params.value.role,
                phone: this.params.value.phone,
                location: this.params.value.location,
                posts: 20,
                followers: '5K',
                following: 500,
            };
            this.contactList.splice(0, 0, user);
            this.searchContacts();
        }

        this.showMessage('User has been saved successfully.');
        this.addContactModal.close();
    }

    deleteUser(user: any = null) {
        this.contactList = this.contactList.filter((d) => d.id != user.id);
        this.searchContacts();
        this.showMessage('User has been deleted successfully.');
    }

    showMessage(msg = '', type = 'success') {
        const toast: any = Swal.mixin({
            toast: true,
            position: 'top',
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
