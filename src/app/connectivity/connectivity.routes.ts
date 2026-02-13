import { Routes } from '@angular/router';

export const CONNECTIVITY_ROUTES: Routes = [
    {
        path: 'call-servers',
        loadComponent: () => import('./call-servers').then((d) => d.CallServersComponent),
        title: 'Call Servers | SmartUCX',
    },
    {
        path: 'lines',
        loadComponent: () => import('./lines').then((d) => d.LinesComponent),
        title: 'Lines | SmartUCX',
    },
    {
        path: 'extensions',
        loadComponent: () => import('./extensions').then((d) => d.ExtensionsComponent),
        title: 'Extensions | SmartUCX',
    },
    {
        path: 'vpw',
        loadComponent: () => import('./vpw').then((d) => d.VPWComponent),
        title: 'VPW | SmartUCX',
    },
    {
        path: 'cas',
        loadComponent: () => import('./cas').then((d) => d.CASComponent),
        title: 'CAS | SmartUCX',
    },
    {
        path: 'sip-3rd-party',
        loadComponent: () => import('./sip-3rd-party').then((d) => d.Sip3rdPartyComponent),
        title: 'SIP/3rd Party Line | SmartUCX',
    },
    {
        path: 'private-wire',
        loadComponent: () => import('./private-wire').then((d) => d.PrivateWireComponent),
        title: 'Private Wire | SmartUCX',
    },
    {
        path: 'trunk',
        loadComponent: () => import('./trunk').then((d) => d.TrunkComponent),
        title: 'Trunk | SmartUCX',
    },
    {
        path: 'intercoms',
        loadComponent: () => import('./intercoms').then((d) => d.IntercomsComponent),
        title: 'Intercom | SmartUCX',
    },
    {
        path: 'call-routing',
        loadComponent: () => import('./call-routing').then((d) => d.CallRoutingComponent),
        title: 'Call Routing | SmartUCX',
    },
    {
        path: 'call-routing/inbound',
        loadComponent: () => import('./inbound-routing').then((d) => d.InboundRoutingComponent),
        title: 'Inbound Routing | SmartUCX',
    },
    {
        path: 'call-routing/outbound',
        loadComponent: () => import('./outbound-routing').then((d) => d.OutboundRoutingComponent),
        title: 'Outbound Routing | SmartUCX',
    },
    {
        path: 'sbc',
        loadComponent: () => import('./sbc').then((d) => d.SBCComponent),
        title: 'SBC | SmartUCX',
    },
    {
        path: 'feature/ivr',
        loadComponent: () => import('./ivr-list').then((d) => d.IvrListComponent),
        title: 'IVR | SmartUCX',
    },
    {
        path: 'feature/black-list',
        loadComponent: () => import('./black-list').then((d) => d.BlackListComponent),
        title: 'Black List | SmartUCX',
    },
    {
        path: 'feature/conference',
        loadComponent: () => import('./conference').then((d) => d.ConferenceComponent),
        title: 'Conference | SmartUCX',
    },
    {
        path: 'feature/customs-destination',
        loadComponent: () => import('./custom-destination').then((d) => d.CustomDestinationComponent),
        title: 'Custom Destination | SmartUCX',
    },
    {
        path: 'feature/misc-destination',
        loadComponent: () => import('./misc-destination').then((d) => d.MiscDestinationComponent),
        title: 'Misc Destination | SmartUCX',
    },
    {
        path: 'sbc-connections',
        loadComponent: () => import('./sbc-connections').then((d) => d.SBCConnectionsComponent),
        title: 'SBC Connections | SmartUCX',
    },
    {
        path: 'sbc-routing',
        loadComponent: () => import('./sbc-routing').then((d) => d.SBCRoutingComponent),
        title: 'SBC Routing | SmartUCX',
    },
    {
        path: 'feature/broadcast',
        loadComponent: () => import('./broadcast').then((d) => d.BroadcastComponent),
        title: 'Broadcast | SmartUCX',
    },
    {
        path: 'feature/music-on-hold',
        loadComponent: () => import('./music-on-hold').then((d) => d.MusicOnHoldComponent),
        title: 'Music on Hold | SmartUCX',
    },
    {
        path: 'feature/paging-intercom',
        loadComponent: () => import('./paging-intercom').then((d) => d.PagingIntercomComponent),
        title: 'Paging & Intercom | SmartUCX',
    },
    {
        path: 'feature/recording',
        loadComponent: () => import('./recording').then((d) => d.RecordingComponent),
        title: 'Recording | SmartUCX',
    },
    {
        path: 'feature/ring-group',
        loadComponent: () => import('./ring-group').then((d) => d.RingGroupComponent),
        title: 'Ring Group | SmartUCX',
    },
    {
        path: 'feature/time-conditions',
        loadComponent: () => import('./time-conditions').then((d) => d.TimeConditionsComponent),
        title: 'Time Conditions | SmartUCX',
    },
    {
        path: 'sbc-status-monitor',
        loadComponent: () => import('./sbc-status-monitor').then((d) => d.SBCStatusMonitorComponent),
        title: 'SBC Status Monitor | SmartUCX',
    },
];

