import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { Store } from '@ngrx/store';

@Component({
    selector: 'app-na',
    standalone: true,
    templateUrl: './na.html',
    imports: [CommonModule, RouterLink]
})
export class NAComponent {
    @Input() showIcon: boolean = true;
    store: any;

    constructor(public storeData: Store<any>) {
        this.initStore();
    }

    async initStore() {
        this.storeData
            .select((d) => d.index)
            .subscribe((d) => {
                this.store = d;
            });
    }
}
