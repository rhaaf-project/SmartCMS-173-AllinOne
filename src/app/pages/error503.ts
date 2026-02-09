import { Component } from '@angular/core';
import { Router, RouterModule } from '@angular/router';
import { Store } from '@ngrx/store';

@Component({
    templateUrl: './error503.html',
    imports: [RouterModule],
})
export class Error503Component {
    store: any;
    constructor(
        public router: Router,
        public storeData: Store<any>,
    ) {
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
