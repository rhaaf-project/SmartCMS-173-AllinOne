import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';

@Component({
    template: `
    <div class="panel" style="padding: 30px;">
        <h5 class="text-xl font-semibold mb-6">Call Routing</h5>
        <p class="text-gray-500 mb-8">Select a routing type below to manage:</p>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <a routerLink="/admin/connectivity/call-routing/inbound" class="block p-6 bg-white dark:bg-[#1b2e4b] rounded-lg border border-gray-200 dark:border-[#3b3f5c] hover:shadow-lg transition-shadow">
                <div class="flex items-center gap-4">
                    <div class="w-12 h-12 rounded-full bg-success/20 flex items-center justify-center">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-success"><path d="M12 5v14M19 12l-7 7-7-7"/></svg>
                    </div>
                    <div>
                        <h6 class="font-semibold text-lg">Inbound Routing</h6>
                        <p class="text-gray-500 text-sm">Manage incoming call routes and DID destinations</p>
                    </div>
                </div>
            </a>
            <a routerLink="/admin/connectivity/call-routing/outbound" class="block p-6 bg-white dark:bg-[#1b2e4b] rounded-lg border border-gray-200 dark:border-[#3b3f5c] hover:shadow-lg transition-shadow">
                <div class="flex items-center gap-4">
                    <div class="w-12 h-12 rounded-full bg-primary/20 flex items-center justify-center">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-primary"><path d="M12 19V5M5 12l7-7 7 7"/></svg>
                    </div>
                    <div>
                        <h6 class="font-semibold text-lg">Outbound Routing</h6>
                        <p class="text-gray-500 text-sm">Configure dial patterns and trunk selection rules</p>
                    </div>
                </div>
            </a>
        </div>
    </div>
    `,
    imports: [CommonModule, RouterModule],
})
export class CallRoutingComponent { }
