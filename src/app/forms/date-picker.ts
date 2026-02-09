import { Component } from '@angular/core';
import { Store } from '@ngrx/store';
import { FormBuilder, FormGroup, FormsModule, ReactiveFormsModule } from '@angular/forms';
import { FlatpickrDefaultsInterface, FlatpickrDirective, provideFlatpickrDefaults } from 'angularx-flatpickr';
import { NgFor, NgIf } from '@angular/common';
import { NouisliderModule } from 'ng2-nouislider';
import { IconCodeComponent } from '../shared/icon/icon-code';
import { IconBellComponent } from '../shared/icon/icon-bell';
import { HighlightModule } from 'ngx-highlightjs';

@Component({
    templateUrl: './date-picker.html',
    imports: [NgIf, NgFor, HighlightModule, FormsModule, ReactiveFormsModule, NouisliderModule, FlatpickrDirective, IconCodeComponent, IconBellComponent],
    providers: [provideFlatpickrDefaults()],
})
export class DatePickerComponent {
    codeArr: any = [];
    toggleCode = (name: string) => {
        if (this.codeArr.includes(name)) {
            this.codeArr = this.codeArr.filter((d: string) => d != name);
        } else {
            this.codeArr.push(name);
        }
    };
    basic: FlatpickrDefaultsInterface;
    dateTime: FlatpickrDefaultsInterface;
    rangeCalendar: FlatpickrDefaultsInterface;
    preloadingTime: FlatpickrDefaultsInterface;

    form1!: FormGroup;
    form2!: FormGroup;
    form3!: FormGroup;
    form4!: FormGroup;

    constructor(
        public storeData: Store<any>,
        public fb: FormBuilder,
    ) {
        this.initStore();
        this.form1 = this.fb.group({
            date1: ['2022-07-05'],
        });
        this.form2 = this.fb.group({
            date2: ['2022-07-05 12:00'],
        });
        this.form3 = this.fb.group({
            date3: ['2022-07-05 to 2022-07-10'],
        });
        this.form4 = this.fb.group({
            date4: ['13:45'],
        });

        this.basic = {
            dateFormat: 'Y-m-d',
            // position: this.store.rtlClass === 'rtl' ? 'auto right' : 'auto left',
            monthSelectorType: 'dropdown',
        };
        this.dateTime = {
            enableTime: true,
            dateFormat: 'Y-m-d H:i',
            // position: this.store.rtlClass === 'rtl' ? 'auto right' : 'auto left',
            monthSelectorType: 'dropdown',
        };
        this.rangeCalendar = {
            dateFormat: 'Y-m-d',
            mode: 'range',
            // position: this.store.rtlClass === 'rtl' ? 'auto right' : 'auto left',
            monthSelectorType: 'dropdown',
        };
        this.preloadingTime = {
            noCalendar: true,
            enableTime: true,
            dateFormat: 'H:i',
            // position: this.store.rtlClass === 'rtl' ? 'auto right' : 'auto left',
            monthSelectorType: 'dropdown',
        };
    }
    store: any;
    async initStore() {
        this.storeData
            .select((d) => d.index)
            .subscribe((d) => {
                this.store = d;
            });
    }

    ngOnInit() {
        this.slider2Update(this.nouiSlider2);
    }

    slider1 = 0;
    slider2 = 0;
    slider3 = 0;
    slider4 = 0;

    nouiMin1 = 20;
    nouiMax1 = 40;
    nouiSlider1: any = [this.nouiMin1, this.nouiMax1];

    nouiSlider2: any = [500.0, 4000.0];
    nouiMin2Perc = 0;
    nouiMax2Perc = 0;

    arrNo = Array.from({ length: 100 }, (_, i) => i);

    slider1Update(range: any) {
        if (range) {
            this.nouiMin1 = range[0];
            this.nouiMax1 = JSON.parse(JSON.stringify(range[1]));
        }
    }
    slider2Update(range: any) {
        if (range) {
            this.nouiSlider2 = range;
            this.nouiMin2Perc = parseFloat((range[0] * 0.01).toFixed(2));
            this.nouiMax2Perc = parseFloat((range[1] * 0.01).toFixed(2));
        }
    }
    selectUpdateValue() {
        this.nouiSlider1 = [this.nouiMin1, this.nouiMax1];
    }

    nouiSlider3: any = 5;
    nouiSlider4: any = 10;
    lockedState = false;
    lockingSlider1 = 0;
    lockingSlider2 = 0;

    setLock() {
        this.lockedState = !this.lockedState;
        if (this.lockedState) {
            this.lockingSlider1 = this.nouiSlider3;
            this.lockingSlider2 = this.nouiSlider4;
        }
    }

    setLockSlider1(value: Number) {
        this.nouiSlider3 = value;
        if (this.lockedState) {
            if (this.lockingSlider1 > this.lockingSlider2) {
                this.nouiSlider4 = this.nouiSlider3 - this.lockingSlider1;
            } else if (this.lockingSlider1 < this.lockingSlider2) {
                this.nouiSlider4 = this.lockingSlider1 + this.nouiSlider3;
            } else {
                this.nouiSlider4 = this.nouiSlider3;
            }
        }
    }

    setLockSlider2(value: Number) {
        this.nouiSlider4 = value;
    }
}
