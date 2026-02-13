import { Component, inject, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { toggleAnimation } from '../shared/animations';
import { environment } from '../../environments/environment';
import Swal from 'sweetalert2';

interface Permission {
    id?: number;
    role: string;
    page_key: string;
    can_view: boolean;
    can_create: boolean;
    can_edit: boolean;
    can_delete: boolean;
}

interface PageGroup {
    label: string;
    pages: { key: string; label: string }[];
}

@Component({
    selector: 'app-policy-privilege',
    standalone: true,
    templateUrl: './policy-privilege.html',
    animations: [toggleAnimation],
    imports: [CommonModule, FormsModule],
})
export class PolicyPrivilegeComponent implements OnInit {
    selectedRole = 'root';
    roles = ['superroot', 'root', 'admin', 'operator'];
    permissions: { [key: string]: { view: boolean; create: boolean; edit: boolean; delete: boolean } } = {};
    isLoading = false;
    isSaving = false;
    hasChanges = false;

    pageGroups: PageGroup[] = [
        {
            label: 'Dashboard',
            pages: [
                { key: 'dashboard', label: 'Dashboard' },
            ]
        },
        {
            label: 'Organization',
            pages: [
                { key: 'organization.company', label: 'Company' },
                { key: 'organization.head_office', label: 'Head Office' },
                { key: 'organization.branch', label: 'Branch' },
                { key: 'organization.sub_branch', label: 'Sub Branch' },
                { key: 'organization.connectivity_diagram', label: 'Connectivity Diagram' },
            ]
        },
        {
            label: 'Connectivity',
            pages: [
                { key: 'connectivity.call_server', label: 'Call Server' },
                { key: 'connectivity.black_list', label: 'Black List' },
                { key: 'connectivity.broadcast', label: 'Broadcast' },
                { key: 'connectivity.conference', label: 'Conference' },
                { key: 'connectivity.custom_destination', label: 'Customs Destination' },
                { key: 'connectivity.ivr', label: 'IVR' },
                { key: 'connectivity.misc_destination', label: 'Misc Destination' },
                { key: 'connectivity.music_on_hold', label: 'Music on Hold' },
                { key: 'connectivity.paging_intercom', label: 'Paging & Intercom' },
                { key: 'connectivity.recording', label: 'Recording' },
                { key: 'connectivity.ring_group', label: 'Ring Group' },
                { key: 'connectivity.time_conditions', label: 'Time Conditions' },
                { key: 'connectivity.lines', label: 'Lines' },
                { key: 'connectivity.extensions', label: 'Extensions' },
                { key: 'connectivity.vpw', label: 'VPW' },
                { key: 'connectivity.cas', label: 'CAS' },
                { key: 'connectivity.intercoms', label: 'Intercoms' },
                { key: 'connectivity.sip_3rd_party', label: 'SIP/3rd Party Line' },
                { key: 'connectivity.private_wire', label: 'Private Wire' },
                { key: 'connectivity.trunk', label: 'Trunk' },
                { key: 'connectivity.call_routing', label: 'Call Routing' },
                { key: 'connectivity.inbound', label: 'Inbound Routing' },
                { key: 'connectivity.outbound', label: 'Outbound Routing' },
            ]
        },
        {
            label: 'SBC',
            pages: [
                { key: 'sbc.sbc', label: 'SBC' },
                { key: 'sbc.connection', label: 'SBC Connection' },
                { key: 'sbc.routing', label: 'SBC Routing' },
                { key: 'sbc.status_monitor', label: 'Status Monitor' },
            ]
        },
        {
            label: 'Voice Gateway',
            pages: [
                { key: 'voice_gateway.analog_fxo', label: 'Analog FXO' },
                { key: 'voice_gateway.analog_fxs', label: 'Analog FXS' },
                { key: 'voice_gateway.e1', label: 'E1' },
                { key: 'voice_gateway.e1_cas', label: 'E1 CAS' },
            ]
        },
        {
            label: 'Recording',
            pages: [
                { key: 'recording.server', label: 'Recording Server' },
                { key: 'recording.channel', label: 'Channel' },
                { key: 'recording.monitor', label: 'Monitor' },
                { key: 'recording.search', label: 'Search' },
            ]
        },
        {
            label: 'Device',
            pages: [
                { key: 'device.turret_device', label: 'Turret Device' },
                { key: 'device.third_party_device', label: '3rd Party Device' },
                { key: 'device.web_device', label: 'Web Device' },
            ]
        },
        {
            label: 'Turret Management',
            pages: [
                { key: 'turret.users', label: 'Turret Users' },
                { key: 'turret.templates', label: 'Templates' },
                { key: 'turret.groups', label: 'Groups' },
                { key: 'turret.policies', label: 'Policies' },
                { key: 'turret.phone_directory', label: 'Phone Directory' },
            ]
        },
        {
            label: 'Network',
            pages: [
                { key: 'network.static_route', label: 'Static Route' },
                { key: 'network.firewall', label: 'Firewall' },
            ]
        },
        {
            label: 'Backup',
            pages: [
                { key: 'backup.backup', label: 'Backup' },
            ]
        },
        {
            label: 'CMS Administration',
            pages: [
                { key: 'cms_admin.user_management', label: 'User Management' },
                { key: 'cms_admin.group', label: 'CMS Group' },
                { key: 'cms_admin.policy_privilege', label: 'Policy / Privilege' },
                { key: 'cms_admin.layout_customizer', label: 'Layout Customizer' },
            ]
        },
        {
            label: 'Logs & Alarm',
            pages: [
                { key: 'logs.system_log', label: 'System Log' },
                { key: 'logs.activity_log', label: 'Activity Log' },
                { key: 'logs.call_log', label: 'Call Log' },
                { key: 'logs.alarm_notification', label: 'Alarm Notification' },
                { key: 'logs.usage_report', label: 'Usage Report' },
            ]
        },
    ];

    private http = inject(HttpClient);

    ngOnInit() {
        this.loadPermissions();
    }

    loadPermissions() {
        this.isLoading = true;
        this.hasChanges = false;
        this.http.get<any>(`${environment.apiUrl}/v1/permissions?role=${this.selectedRole}`).subscribe({
            next: (res) => {
                this.permissions = res.data || {};
                this.isLoading = false;
            },
            error: () => {
                this.permissions = {};
                this.isLoading = false;
            }
        });
    }

    onRoleChange() {
        if (this.hasChanges) {
            Swal.fire({
                title: 'Unsaved Changes',
                text: 'You have unsaved changes. Switch role anyway?',
                icon: 'warning',
                showCancelButton: true,
                confirmButtonText: 'Switch',
                cancelButtonText: 'Stay'
            }).then((result) => {
                if (result.isConfirmed) {
                    this.loadPermissions();
                }
            });
        } else {
            this.loadPermissions();
        }
    }

    getPermission(pageKey: string, action: string): boolean {
        return this.permissions[pageKey]?.[action as keyof typeof this.permissions[typeof pageKey]] ?? false;
    }

    togglePermission(pageKey: string, action: string) {
        if (this.selectedRole === 'superroot') {
            Swal.fire('Warning', 'Superroot permissions cannot be modified', 'warning');
            return;
        }

        if (!this.permissions[pageKey]) {
            this.permissions[pageKey] = { view: false, create: false, edit: false, delete: false };
        }

        const key = action as keyof typeof this.permissions[typeof pageKey];
        (this.permissions[pageKey] as any)[key] = !this.permissions[pageKey][key];

        // If disabling view, disable all others too
        if (action === 'view' && !this.permissions[pageKey].view) {
            this.permissions[pageKey].create = false;
            this.permissions[pageKey].edit = false;
            this.permissions[pageKey].delete = false;
        }

        // If enabling create/edit/delete, auto-enable view
        if (action !== 'view' && (this.permissions[pageKey] as any)[key]) {
            this.permissions[pageKey].view = true;
        }

        this.hasChanges = true;
    }

    isAllPermissionsEnabled(pageKey: string): boolean {
        const p = this.permissions[pageKey];
        return p ? p.view && p.create && p.edit && p.delete : false;
    }

    toggleAllPermissions(pageKey: string) {
        if (this.selectedRole === 'superroot') return;
        if (!this.permissions[pageKey]) {
            this.permissions[pageKey] = { view: false, create: false, edit: false, delete: false };
        }
        const allOn = this.isAllPermissionsEnabled(pageKey);
        this.permissions[pageKey].view = !allOn;
        this.permissions[pageKey].create = !allOn;
        this.permissions[pageKey].edit = !allOn;
        this.permissions[pageKey].delete = !allOn;
        this.hasChanges = true;
    }

    get allViewEnabled(): boolean {
        return this.pageGroups.every(group =>
            group.pages.every(p => this.isAllPermissionsEnabled(p.key))
        );
    }

    toggleAllView() {
        if (this.selectedRole === 'superroot') return;
        const allEnabled = this.allViewEnabled;
        this.pageGroups.forEach(group => {
            group.pages.forEach(p => {
                if (!this.permissions[p.key]) {
                    this.permissions[p.key] = { view: false, create: false, edit: false, delete: false };
                }
                this.permissions[p.key].view = !allEnabled;
                this.permissions[p.key].create = !allEnabled;
                this.permissions[p.key].edit = !allEnabled;
                this.permissions[p.key].delete = !allEnabled;
            });
        });
        this.hasChanges = true;
    }

    toggleGroupView(group: PageGroup) {
        if (this.selectedRole === 'superroot') return;

        // Check if all pages in group have view enabled
        const allEnabled = group.pages.every(p => this.getPermission(p.key, 'view'));

        group.pages.forEach(p => {
            if (!this.permissions[p.key]) {
                this.permissions[p.key] = { view: false, create: false, edit: false, delete: false };
            }
            this.permissions[p.key].view = !allEnabled;
            if (allEnabled) {
                // Disable all if disabling view
                this.permissions[p.key].create = false;
                this.permissions[p.key].edit = false;
                this.permissions[p.key].delete = false;
            }
        });
        this.hasChanges = true;
    }

    savePermissions() {
        if (this.selectedRole === 'superroot') {
            Swal.fire('Warning', 'Superroot permissions cannot be modified', 'warning');
            return;
        }

        this.isSaving = true;
        const payload: any[] = [];

        // Collect all permissions for the selected role
        for (const group of this.pageGroups) {
            for (const page of group.pages) {
                const perm = this.permissions[page.key] || { view: false, create: false, edit: false, delete: false };
                payload.push({
                    role: this.selectedRole,
                    page_key: page.key,
                    can_view: perm.view ? 1 : 0,
                    can_create: perm.create ? 1 : 0,
                    can_edit: perm.edit ? 1 : 0,
                    can_delete: perm.delete ? 1 : 0,
                });
            }
        }

        this.http.post<any>(`${environment.apiUrl}/v1/role-permissions/bulk`, { permissions: payload }).subscribe({
            next: () => {
                Swal.fire('Success', `Permissions for "${this.selectedRole}" saved successfully`, 'success');
                this.hasChanges = false;
                this.isSaving = false;
            },
            error: (err) => {
                Swal.fire('Error', err.error?.error || 'Failed to save permissions', 'error');
                this.isSaving = false;
            }
        });
    }

    getRoleBadgeClass(role: string): string {
        switch (role) {
            case 'superroot': return 'bg-danger/20 text-danger';
            case 'root': return 'bg-warning/20 text-warning';
            case 'admin': return 'bg-primary/20 text-primary';
            case 'operator': return 'bg-info/20 text-info';
            default: return 'bg-dark/20 text-dark';
        }
    }

    getRoleLabel(role: string): string {
        switch (role) {
            case 'superroot': return 'Super Root (Product Owner)';
            case 'root': return 'Root (Company Admin)';
            case 'admin': return 'Admin (Manager)';
            case 'operator': return 'Operator (Staff)';
            default: return role;
        }
    }
}
