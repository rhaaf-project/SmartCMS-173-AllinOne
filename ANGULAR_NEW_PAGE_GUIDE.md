# Angular New Page & Sidebar Integration Guide

## SmartUCX CMS - Angular Standalone Components

This guide documents the complete process for creating new pages and integrating them into the sidebar navigation in the Angular frontend of SmartUCX CMS.

---

## Table of Contents
1. [Project Structure Overview](#project-structure-overview)
2. [Creating a New Page](#creating-a-new-page)
3. [Adding Routes](#adding-routes)
4. [Integrating with Sidebar](#integrating-with-sidebar)
5. [Common Patterns](#common-patterns)
6. [Troubleshooting](#troubleshooting)
7. [Deployment](#deployment)

---

## Project Structure Overview

```
CMS/src/app/
├── app.route.ts                 # Main routing configuration
├── layouts/
│   ├── sidebar.html             # Sidebar navigation HTML
│   └── sidebar.ts               # Sidebar component logic
├── organization/                # Example module
│   ├── organization.routes.ts   # Module-specific routes
│   ├── company/
│   │   ├── company-list.ts      # List component
│   │   └── company-form.ts      # Form component (Create/Edit/View)
│   └── branch/
│       ├── branch-list.ts
│       └── branch-form.ts
├── connectivity/                # Example module
│   ├── connectivity.routes.ts
│   ├── call-servers.ts
│   ├── lines.ts
│   └── extensions.ts
└── cms-admin/                   # CMS administration
    ├── cms-users.ts
    └── layout-customizer.ts
```

**Key Points:**
- Angular 20.3.10 with **standalone components** (no NgModules)
- TypeScript strict mode enabled
- Lazy-loaded routes using `loadComponent` and `loadChildren`
- Manual sidebar configuration (not auto-generated)
- **⚠️ CRITICAL: All data MUST be fetched from API (`api.php`) - NEVER use localStorage as primary data source**
- localStorage is ONLY for caching/fallback, always fetch fresh data from API on component init

---

## Creating a New Page

### Step 1: Choose Your Module Location

Decide where your page belongs:
- **Organization**: Company structure (Company, HO, Branch, Sub-Branch)
- **Connectivity**: Call infrastructure (Lines, Extensions, Trunks, SBC)
- **Logs**: System/Activity/Call logs
- **CMS Admin**: CMS user management, settings

### Step 2: Create Component File

**Pattern 1: Simple List Component (e.g., call-servers.ts)**

```typescript
// src/app/connectivity/call-servers.ts
import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../environments/environment';
import { Store } from '@ngrx/store';

@Component({
    templateUrl: './call-servers.html',
    imports: [CommonModule],
    standalone: true
})
export class CallServersComponent implements OnInit {
    store: any;
    isLoading = true;
    callServers: any[] = [];
    private http = inject(HttpClient);

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

    ngOnInit() {
        this.loadData();
    }

    loadData() {
        this.isLoading = true;
        const apiUrl = `${environment.apiUrl}/v1/connectivity/call-servers`;

        this.http.get<any>(apiUrl).subscribe({
            next: (response) => {
                this.callServers = response.data || [];
                this.isLoading = false;
            },
            error: (error) => {
                console.error('Failed to load call servers:', error);
                this.isLoading = false;
            }
        });
    }
}
```

**Pattern 2: List + Form (CRUD Operations)**

For modules with Create/Edit/View functionality, create two files:

**List Component (organization/company/company-list.ts):**
```typescript
import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../../environments/environment';

@Component({
    templateUrl: './company-list.html',
    imports: [CommonModule, RouterLink],
    standalone: true
})
export class CompanyListComponent implements OnInit {
    companies: any[] = [];
    isLoading = true;
    private http = inject(HttpClient);

    ngOnInit() {
        this.loadCompanies();
    }

    loadCompanies() {
        const apiUrl = `${environment.apiUrl}/v1/organization/companies`;

        this.http.get<any>(apiUrl).subscribe({
            next: (response) => {
                this.companies = response.data || [];
                this.isLoading = false;
            },
            error: (error) => {
                console.error('Failed to load companies:', error);
                this.isLoading = false;
            }
        });
    }

    deleteCompany(id: number) {
        if (confirm('Are you sure you want to delete this company?')) {
            const apiUrl = `${environment.apiUrl}/v1/organization/companies/${id}`;

            this.http.delete(apiUrl).subscribe({
                next: () => {
                    this.loadCompanies(); // Reload list
                },
                error: (error) => {
                    console.error('Failed to delete company:', error);
                }
            });
        }
    }
}
```

**Form Component (organization/company/company-form.ts):**
```typescript
import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, ActivatedRoute } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../../environments/environment';

@Component({
    templateUrl: './company-form.html',
    imports: [CommonModule, FormsModule],
    standalone: true
})
export class CompanyFormComponent implements OnInit {
    company: any = {
        name: '',
        address: '',
        phone: '',
        is_active: true
    };
    isEditMode = false;
    isViewMode = false;
    isLoading = false;

    private http = inject(HttpClient);
    private router = inject(Router);
    private route = inject(ActivatedRoute);

    ngOnInit() {
        const id = this.route.snapshot.paramMap.get('id');
        const path = this.route.snapshot.routeConfig?.path;

        this.isEditMode = path?.includes('edit') || false;
        this.isViewMode = !path?.includes('edit') && !path?.includes('create') && !!id;

        if (id) {
            this.loadCompany(+id);
        }
    }

    loadCompany(id: number) {
        this.isLoading = true;
        const apiUrl = `${environment.apiUrl}/v1/organization/companies/${id}`;

        this.http.get<any>(apiUrl).subscribe({
            next: (response) => {
                this.company = response.data;
                this.isLoading = false;
            },
            error: (error) => {
                console.error('Failed to load company:', error);
                this.isLoading = false;
            }
        });
    }

    onSubmit() {
        this.isLoading = true;
        const apiUrl = this.isEditMode
            ? `${environment.apiUrl}/v1/organization/companies/${this.company.id}`
            : `${environment.apiUrl}/v1/organization/companies`;

        const method = this.isEditMode ? this.http.put(apiUrl, this.company) : this.http.post(apiUrl, this.company);

        method.subscribe({
            next: () => {
                this.router.navigate(['/admin/organization/company']);
            },
            error: (error) => {
                console.error('Failed to save company:', error);
                this.isLoading = false;
            }
        });
    }

    cancel() {
        this.router.navigate(['/admin/organization/company']);
    }
}
```

### Step 3: Create HTML Template

Create corresponding `.html` file (e.g., `call-servers.html`, `company-list.html`, `company-form.html`)

**Example List Template:**
```html
<div>
    <div class="panel">
        <div class="flex items-center justify-between mb-5">
            <h5 class="text-lg font-semibold dark:text-white-light">Call Servers</h5>
            <a routerLink="/admin/connectivity/call-servers/create" class="btn btn-primary">
                Add New Call Server
            </a>
        </div>

        <div *ngIf="isLoading" class="text-center py-10">
            <span class="animate-spin border-4 border-primary border-l-transparent rounded-full w-10 h-10 inline-block"></span>
        </div>

        <div *ngIf="!isLoading" class="table-responsive">
            <table class="table-hover">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>IP Address</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <tr *ngFor="let server of callServers">
                        <td>{{ server.name }}</td>
                        <td>{{ server.ip_address }}</td>
                        <td>
                            <span [ngClass]="server.is_active ? 'badge-success' : 'badge-danger'">
                                {{ server.is_active ? 'Active' : 'Inactive' }}
                            </span>
                        </td>
                        <td>
                            <a [routerLink]="['/admin/connectivity/call-servers/edit', server.id]" class="btn btn-sm btn-primary">Edit</a>
                            <button (click)="deleteServer(server.id)" class="btn btn-sm btn-danger ml-2">Delete</button>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</div>
```

---

## Adding Routes

### Step 1: Create/Update Module Routes File

**For new module (e.g., logs/logs.routes.ts):**

```typescript
import { Routes } from '@angular/router';

export const logsRoutes: Routes = [
    {
        path: 'system-logs',
        loadComponent: () => import('./system-logs').then((d) => d.SystemLogsComponent),
        title: 'System Logs | SmartUCX',
    },
    {
        path: 'activity-logs',
        loadComponent: () => import('./activity-logs').then((d) => d.ActivityLogsComponent),
        title: 'Activity Logs | SmartUCX',
    },
    {
        path: 'call-logs',
        loadComponent: () => import('./call-logs').then((d) => d.CallLogsComponent),
        title: 'Call Logs | SmartUCX',
    },
];
```

**For existing module (add to connectivity.routes.ts):**

```typescript
export const CONNECTIVITY_ROUTES: Routes = [
    // ... existing routes ...
    {
        path: 'new-feature',
        loadComponent: () => import('./new-feature').then((d) => d.NewFeatureComponent),
        title: 'New Feature | SmartUCX',
    },
];
```

**For CRUD routes (List + Create/Edit/View):**

```typescript
export const ORGANIZATION_ROUTES: Routes = [
    // List route
    {
        path: 'company',
        loadComponent: () => import('./company/company-list').then((d) => d.CompanyListComponent),
        data: { title: 'Company | SmartUCX' },
    },
    // Create route
    {
        path: 'company/create',
        loadComponent: () => import('./company/company-form').then((d) => d.CompanyFormComponent),
        data: { title: 'Create Company | SmartUCX' },
    },
    // Edit route
    {
        path: 'company/edit/:id',
        loadComponent: () => import('./company/company-form').then((d) => d.CompanyFormComponent),
        data: { title: 'Edit Company | SmartUCX' },
    },
    // View route
    {
        path: 'company/:id',
        loadComponent: () => import('./company/company-form').then((d) => d.CompanyFormComponent),
        data: { title: 'View Company | SmartUCX' },
    },
];
```

### Step 2: Register Module Routes in Main app.route.ts

**File:** `src/app/app.route.ts`

Add lazy-loaded module routes inside the `admin` protected route:

```typescript
export const routes: Routes = [
    {
        path: 'admin',
        component: AppLayout,
        canActivate: [AuthGuard],
        children: [
            // ... existing routes ...

            // NEW MODULE: Add this line
            {
                path: 'logs',
                loadChildren: () => import('./logs/logs.routes').then((d) => d.logsRoutes)
            },
        ],
    },
];
```

**Routing Patterns:**
- `loadComponent`: Lazy load a single component
- `loadChildren`: Lazy load multiple routes from a module
- `data: { title }`: Sets browser tab title
- `title`: Alternative way to set tab title (used in newer routes)

---

## Integrating with Sidebar

**File:** `src/app/layouts/sidebar.html`

### Pattern 1: Single Menu Item (No Submenu)

```html
<!-- Dashboard (no submenu) -->
<li class="menu nav-item">
    <a routerLink="/" class="nav-link group" routerLinkActive="active"
        [routerLinkActiveOptions]="{exact: true}" (click)="toggleMobileMenu()">
        <div class="flex items-center">
            <icon-menu-dashboard class="shrink-0 group-hover:!text-primary" />
            <span class="text-black dark:text-[#506690] dark:group-hover:text-white-dark ltr:pl-3 rtl:pr-3">
                Dashboard
            </span>
        </div>
    </a>
</li>
```

### Pattern 2: Accordion Menu (With Submenu)

```html
<!-- Organization (with submenu) -->
<li class="accordion menu nav-item">
    <button type="button" class="nav-link group w-full"
        [ngClass]="{ active: activeDropdown.includes('organization') }"
        (click)="toggleAccordion('organization')">
        <div class="flex items-center">
            <icon-menu-contacts class="shrink-0 group-hover:!text-primary" />
            <span class="text-black dark:text-[#506690] dark:group-hover:text-white-dark ltr:pl-3 rtl:pr-3">
                Organization
            </span>
        </div>
        <div [ngClass]="{ 'rtl:rotate-90 -rotate-90': !activeDropdown.includes('organization') }">
            <icon-caret-down />
        </div>
    </button>
    <div [@slideDownUp]="!activeDropdown.includes('organization')" class="accordion-content">
        <ul class="sub-menu text-gray-500">
            <li><a routerLink="/admin/organization/company" routerLinkActive="active"
                    (click)="toggleMobileMenu()">Company</a></li>
            <li><a routerLink="/admin/organization/head-office" routerLinkActive="active"
                    (click)="toggleMobileMenu()">Head Office</a></li>
            <li><a routerLink="/admin/organization/branch" routerLinkActive="active"
                    (click)="toggleMobileMenu()">Branch</a></li>
        </ul>
    </div>
</li>
```

### Pattern 3: Nested Submenu (3 Levels Deep)

```html
<!-- Connectivity > Line (nested submenu) -->
<li class="accordion menu nav-item">
    <button type="button" class="nav-link group w-full"
        [ngClass]="{ active: activeDropdown.includes('connectivity') }"
        (click)="toggleAccordion('connectivity')">
        <div class="flex items-center">
            <icon-menu-components class="shrink-0 group-hover:!text-primary" />
            <span class="text-black dark:text-[#506690] dark:group-hover:text-white-dark ltr:pl-3 rtl:pr-3">
                Connectivity
            </span>
        </div>
        <div [ngClass]="{ 'rtl:rotate-90 -rotate-90': !activeDropdown.includes('connectivity') }">
            <icon-caret-down />
        </div>
    </button>
    <div [@slideDownUp]="!activeDropdown.includes('connectivity')" class="accordion-content">
        <ul class="sub-menu text-gray-500">
            <li><a routerLink="/admin/connectivity/call-servers" routerLinkActive="active"
                    (click)="toggleMobileMenu()">Call Server</a></li>

            <!-- NESTED SUBMENU: Line -->
            <li class="accordion menu nav-item">
                <button type="button"
                    class="w-full before:h-[5px] before:w-[5px] before:rounded before:bg-gray-300 hover:bg-gray-100 dark:text-[#888ea8] dark:hover:bg-gray-900 ltr:before:mr-2 rtl:before:ml-2"
                    (click)="toggleAccordion('line')">
                    Line
                    <div class="ltr:ml-auto rtl:mr-auto"
                        [ngClass]="{ 'rtl:rotate-90 -rotate-90': !activeDropdown.includes('line') }">
                        <icon-carets-down [fill]="true" class="h-4 w-4" />
                    </div>
                </button>
                <div [@slideDownUp]="!activeDropdown.includes('line')" class="accordion-content">
                    <ul class="sub-menu text-gray-500 !pl-4">
                        <li><a routerLink="/admin/connectivity/lines" routerLinkActive="active"
                                (click)="toggleMobileMenu()">Line</a></li>
                        <li><a routerLink="/admin/connectivity/extensions" routerLinkActive="active"
                                (click)="toggleMobileMenu()">Extension</a></li>
                        <li><a routerLink="/admin/connectivity/vpw" routerLinkActive="active"
                                (click)="toggleMobileMenu()">VPW</a></li>
                    </ul>
                </div>
            </li>
        </ul>
    </div>
</li>
```

### Sidebar Component Logic

**File:** `src/app/layouts/sidebar.ts`

Ensure the accordion key is handled:

```typescript
export class SidebarComponent {
    activeDropdown: string[] = [];

    toggleAccordion(name: string) {
        if (this.activeDropdown.includes(name)) {
            this.activeDropdown = this.activeDropdown.filter((d) => d !== name);
        } else {
            this.activeDropdown.push(name);
        }
    }

    toggleMobileMenu() {
        // Close mobile menu when item clicked
        this.storeData.dispatch({ type: 'toggleSidebar' });
    }
}
```

### Available Sidebar Icons

Common icons from `icon-menu-*`:
- `icon-menu-dashboard` - Dashboard/Home
- `icon-menu-contacts` - Organization/People
- `icon-menu-components` - Connectivity/Links
- `icon-menu-elements` - SBC/Network
- `icon-menu-chat` - Voice/Communication
- `icon-menu-notes` - Recording/Logs
- `icon-menu-widgets` - Devices
- `icon-menu-tables` - Turret Management
- `icon-menu-drag-and-drop` - Network/Topology
- `icon-menu-calendar` - Backup/Scheduling
- `icon-menu-authentication` - CMS Admin
- `icon-menu-charts` - Logs/Analytics

---

## Common Patterns

### 1. Environment Configuration

**File:** `src/environments/environment.ts`

```typescript
export const environment = {
    production: false,
    apiUrl: 'http://localhost:8000/api',
};
```

All API calls should use `${environment.apiUrl}/v1/module/endpoint`

### 2. API Response Structure

Laravel API returns:

```json
{
    "success": true,
    "data": [...],  // or single object
    "message": "Success"
}
```

Handle errors:

```typescript
this.http.get<any>(apiUrl).subscribe({
    next: (response) => {
        this.items = response.data || [];
    },
    error: (error) => {
        console.error('Failed to load:', error);
        // Show error notification to user
    }
});
```

### 3. Authentication Token

All API calls automatically include token via HTTP interceptor (Sanctum).

### 4. Loading States

Always show loading indicator:

```typescript
isLoading = true;

loadData() {
    this.isLoading = true;
    this.http.get(apiUrl).subscribe({
        next: (response) => {
            // ... handle data
            this.isLoading = false;
        },
        error: (error) => {
            this.isLoading = false;
        }
    });
}
```

### 5. Dark Mode Support

Use Tailwind classes that support dark mode:

```html
<span class="text-black dark:text-white">Text</span>
<div class="bg-white dark:bg-[#0e1726]">Container</div>
```

---

## Troubleshooting

### Issue 1: Route Not Working (404)

**Symptoms:** Clicking sidebar link shows 404 or blank page

**Solution:**
1. Check `app.route.ts` - ensure module is registered in `admin` children
2. Check module routes file - ensure path matches sidebar link
3. Verify component export name matches import in routes file

### Issue 2: Sidebar Item Not Showing

**Symptoms:** Added sidebar item but it doesn't appear

**Solution:**
1. Check `sidebar.html` syntax - ensure proper HTML structure
2. Verify accordion key in `toggleAccordion()` matches between button and state
3. Check for missing closing tags

### Issue 3: Component Not Loading

**Symptoms:** Console shows "Failed to load component" or import error

**Solution:**
1. Ensure component has `standalone: true` in `@Component()` decorator
2. Check all imports are declared in `imports: []` array
3. Verify file path in `loadComponent()` matches actual file location
4. Check component class name matches export: `export class MyComponent`

### Issue 4: Nested Submenu Not Opening

**Symptoms:** Clicking nested submenu button doesn't expand

**Solution:**
1. Ensure unique accordion key (e.g., 'line', 'feature', not 'connectivity')
2. Check `[@slideDownUp]` animation directive is present
3. Verify `activeDropdown.includes('key')` matches button click handler

### Issue 5: API Not Returning Data

**Symptoms:** Component loads but no data appears, or errors in console

**Solution:**
1. Check browser Network tab - verify API endpoint returns 200 status
2. Verify Laravel backend route exists: `php artisan route:list | grep endpoint`
3. Check API response structure matches frontend expectations
4. Ensure authentication token is included (check headers in Network tab)

### Issue 6: TypeScript Compilation Errors

**Common errors:**
- `Property 'X' does not exist on type 'Y'` - Add type annotations or use `any`
- `Cannot find module` - Check import paths (case-sensitive on Linux)
- BOM character at file start - Use `git restore` to fix encoding

**Solutions:**
```typescript
// Use explicit types
callServers: any[] = [];

// Or define interface
interface CallServer {
    id: number;
    name: string;
    ip_address: string;
    is_active: boolean;
}
callServers: CallServer[] = [];
```

---

## Complete Example: Adding "System Logs" Page

### Step 1: Create Component Files

**File:** `src/app/logs/system-logs.ts`

```typescript
import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../environments/environment';
import { Store } from '@ngrx/store';

@Component({
    templateUrl: './system-logs.html',
    imports: [CommonModule],
    standalone: true
})
export class SystemLogsComponent implements OnInit {
    store: any;
    isLoading = true;
    logs: any[] = [];
    private http = inject(HttpClient);

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

    ngOnInit() {
        this.loadLogs();
    }

    loadLogs() {
        this.isLoading = true;
        const apiUrl = `${environment.apiUrl}/v1/logs/system-logs`;

        this.http.get<any>(apiUrl).subscribe({
            next: (response) => {
                this.logs = response.data || [];
                this.isLoading = false;
            },
            error: (error) => {
                console.error('Failed to load system logs:', error);
                this.isLoading = false;
            }
        });
    }
}
```

**File:** `src/app/logs/system-logs.html`

```html
<div>
    <div class="panel">
        <h5 class="text-lg font-semibold dark:text-white-light mb-5">System Logs</h5>

        <div *ngIf="isLoading" class="text-center py-10">
            <span class="animate-spin border-4 border-primary border-l-transparent rounded-full w-10 h-10 inline-block"></span>
        </div>

        <div *ngIf="!isLoading" class="table-responsive">
            <table class="table-hover">
                <thead>
                    <tr>
                        <th>Level</th>
                        <th>Message</th>
                        <th>IP Address</th>
                        <th>Created At</th>
                    </tr>
                </thead>
                <tbody>
                    <tr *ngFor="let log of logs">
                        <td>
                            <span [ngClass]="{
                                'badge-danger': log.level === 'error',
                                'badge-warning': log.level === 'warning',
                                'badge-info': log.level === 'info'
                            }">{{ log.level }}</span>
                        </td>
                        <td>{{ log.message }}</td>
                        <td>{{ log.ip_address }}</td>
                        <td>{{ log.created_at | date:'short' }}</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</div>
```

### Step 2: Create Module Routes

**File:** `src/app/logs/logs.routes.ts`

```typescript
import { Routes } from '@angular/router';

export const logsRoutes: Routes = [
    {
        path: 'system-logs',
        loadComponent: () => import('./system-logs').then((d) => d.SystemLogsComponent),
        title: 'System Logs | SmartUCX',
    },
    {
        path: 'activity-logs',
        loadComponent: () => import('./activity-logs').then((d) => d.ActivityLogsComponent),
        title: 'Activity Logs | SmartUCX',
    },
    {
        path: 'call-logs',
        loadComponent: () => import('./call-logs').then((d) => d.CallLogsComponent),
        title: 'Call Logs | SmartUCX',
    },
];
```

### Step 3: Register in Main Routes

**File:** `src/app/app.route.ts` (add inside `admin` children array):

```typescript
{
    path: 'logs',
    loadChildren: () => import('./logs/logs.routes').then((d) => d.logsRoutes)
},
```

### Step 4: Add to Sidebar

**File:** `src/app/layouts/sidebar.html` (add before closing `</ul>`):

```html
<!-- 12. Alarm & Log -->
<li class="accordion menu nav-item">
    <button type="button" class="nav-link group w-full"
        [ngClass]="{ active: activeDropdown.includes('alarm-log') }"
        (click)="toggleAccordion('alarm-log')">
        <div class="flex items-center">
            <icon-menu-charts class="shrink-0 group-hover:!text-primary" />
            <span class="text-black dark:text-[#506690] dark:group-hover:text-white-dark ltr:pl-3 rtl:pr-3">
                Alarm & Log
            </span>
        </div>
        <div [ngClass]="{ 'rtl:rotate-90 -rotate-90': !activeDropdown.includes('alarm-log') }">
            <icon-caret-down />
        </div>
    </button>
    <div [@slideDownUp]="!activeDropdown.includes('alarm-log')" class="accordion-content">
        <ul class="sub-menu text-gray-500">
            <li><a routerLink="/admin/logs/system-logs" routerLinkActive="active"
                    (click)="toggleMobileMenu()">System Log</a></li>
            <li><a routerLink="/admin/logs/activity-logs" routerLinkActive="active"
                    (click)="toggleMobileMenu()">Activity Log</a></li>
            <li><a routerLink="/admin/logs/call-logs" routerLinkActive="active"
                    (click)="toggleMobileMenu()">Call Log</a></li>
        </ul>
    </div>
</li>
```

### Step 5: Test

1. Start dev server: `npm start`
2. Navigate to `http://localhost:4200/admin`
3. Click "Alarm & Log" in sidebar
4. Click "System Log" submenu item
5. Verify page loads and shows data (or loading spinner)

---

## Summary Checklist

When adding a new page to SmartUCX CMS Angular frontend:

- [ ] Create component `.ts` file with `standalone: true`
- [ ] Create component `.html` template
- [ ] Add route to module routes file (or create new one)
- [ ] Register module in `app.route.ts` (inside `admin` children)
- [ ] Add sidebar menu item in `sidebar.html`
- [ ] Ensure accordion key is unique and matches in both button and state check
- [ ] Test navigation from sidebar to new page
- [ ] Verify API endpoint exists and returns data
- [ ] Test loading states and error handling
- [ ] Test dark mode appearance

---

## Key Differences: Angular vs Filament

| Aspect | Angular (Frontend) | Filament (Backend) |
|--------|-------------------|-------------------|
| **Routing** | Manual in `app.route.ts` + module routes | Auto-discovered from Resource classes |
| **Sidebar** | Manual in `sidebar.html` | Auto-generated from Resource properties |
| **Components** | TypeScript + HTML files | PHP Resource classes |
| **Menu Nesting** | HTML structure with `<li class="accordion">` | `$navigationGroup` + `$navigationParentItem` |
| **Icons** | Icon components (`<icon-menu-*>`) | Heroicon strings (`'heroicon-o-*'`) |
| **Files Modified** | 3-4 files (component, routes, sidebar) | 1-2 files (Resource, optional Provider) |

**CRITICAL:** CMS_MENU_FIX_GUIDE.md is for **Filament only** (Laravel backend admin panel). It does NOT apply to Angular frontend navigation!

---

**Last Updated:** 2026-02-03
**Angular Version:** 20.3.10
**Project:** SmartUCX CMS - Angular Standalone Components

---

## 🚧 Not Available (Placeholder) Page

For menus that don't have a page yet, use the **NAComponent** as a placeholder.

### Using NAComponent

**Location:** `src/app/shared/na/na.ts` and `na.html`

**To use for a new menu item:**

1. **In your routes file**, point to NAComponent:

```typescript
// Example in connectivity.routes.ts
{
    path: 'future-feature',
    loadComponent: () => import('../shared/na/na').then((d) => d.NAComponent),
    title: 'Future Feature | SmartUCX',
},
```

2. **In sidebar.html**, add the menu item normally:

```html
<li><a routerLink="/admin/connectivity/future-feature" routerLinkActive="active"
        (click)="toggleMobileMenu()">Future Feature</a></li>
```

The NAComponent displays:
- Warning icon
- "Under Development" title
- Description text
- "Back to Dashboard" button

---

## 🏗️ Project Architecture Overview

### File Structure Relationship

```
┌─────────────────────────────────────────────────────────────────┐
│  BROWSER (localhost:4200)                                        │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  Angular Frontend                                            │ │
│  │  ├── app.route.ts -----------> Routes map URLs to components │ │
│  │  ├── layouts/sidebar.html ---> Navigation menu structure     │ │
│  │  └── [module]/[component].ts -> Business logic + API calls   │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                              │                                    │
│                              │ HTTP Requests                      │
│                              ▼                                    │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  api.php (localhost:8000)                                    │ │
│  │  Simple PHP router that connects to MySQL                    │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                              │                                    │
│                              │ SQL Queries                        │
│                              ▼                                    │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  MariaDB (db_ucx)                                            │ │
│  │  Database tables for all CMS data                            │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Key Files and Their Purposes

| File | Purpose |
|------|---------|
| `app.route.ts` | Main routing configuration - maps URL paths to components |
| `layouts/sidebar.html` | Navigation menu HTML structure |
| `layouts/sidebar.ts` | Sidebar component logic (accordion states, mobile menu) |
| `[module]/[module].routes.ts` | Module-specific routes (e.g., connectivity.routes.ts) |
| `[module]/[component].ts` | Page component with business logic |
| `[module]/[component].html` | Page template HTML |
| `environments/environment.ts` | API URL configuration |
| `api.php` | Backend API router (PHP) |

### Adding a New Page - Step by Step

```
1. CREATE Component Files
   └── src/app/[module]/[page-name].ts
   └── src/app/[module]/[page-name].html

2. ADD Route  
   └── src/app/[module]/[module].routes.ts
       └── Add path + loadComponent entry

3. REGISTER Module (if new module)
   └── src/app/app.route.ts  
       └── Add loadChildren entry in admin children

4. ADD Sidebar Menu
   └── src/app/layouts/sidebar.html
       └── Add <li> or accordion section
```

---

## 🔌 API Connection Details

### Environment Configuration

**File:** `src/environments/environment.ts`

```typescript
export const environment = {
    production: false,
    apiUrl: 'http://localhost:8000/api',
};
```

### Starting Development Servers

```bash
# Terminal 1: Angular Frontend (port 4200)
cd D:\02____WORKS\04___Server\Projects\CMS\VISTO\CMS
npm start

# Terminal 2: PHP API Backend (port 8000)
cd D:\02____WORKS\04___Server\Projects\CMS\VISTO\CMS
C:\wamp64\bin\php\php8.4.15\php.exe -S localhost:8000 api.php
```

### Making API Calls

```typescript
import { HttpClient } from '@angular/common/http';
import { environment } from '../../environments/environment';

// In component:
private http = inject(HttpClient);

// GET request
this.http.get<any>(`${environment.apiUrl}/v1/[endpoint]`).subscribe({
    next: (response) => {
        this.data = response.data || [];
    },
    error: (error) => {
        console.error('Failed to load:', error);
    }
});

// POST request
this.http.post<any>(`${environment.apiUrl}/v1/[endpoint]`, payload).subscribe({
    next: (response) => { /* success */ },
    error: (error) => { /* handle error */ }
});
```

### Common API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/call-servers` | GET | List call servers |
| `/v1/sbcs` | GET | List SBC connections |
| `/v1/sbc-routes` | GET/POST/PUT/DELETE | SBC routing CRUD |
| `/v1/customers` | GET | List customers |
| `/v1/branches` | GET | List branches |
| `/v1/users` | GET | List CMS users |

### API Response Format

```json
{
    "success": true,
    "data": [...],
    "message": "Success"
}
```

---

## 🎨 Theming and Styling

### Primary Color Configuration

**File:** `tailwind.config.js` - Line 20

```javascript
primary: {
    DEFAULT: '#0264c2',  // Main primary color (rgb 2, 100, 194)
    light: '#eaf1ff',
    'dark-light': 'rgba(67,97,238,.15)',
},
```

### Color Theme CSS Overrides

**File:** `src/assets/css/color-themes.css`

Contains overrides for different color themes (orange, red, green, purple, cyan) including:
- Button styles
- Text colors
- Border colors
- Sidebar active/hover states

### Dark Mode

App defaults to dark mode. Use Tailwind dark mode classes:

```html
<div class="bg-white dark:bg-[#0e1726]">Content</div>
<span class="text-black dark:text-white">Text</span>
```

---

## 🤖 Quick Reference for AI Agents

### Common Issues and Fixes

| Issue | Cause | Solution |
|-------|-------|----------|
| Build fails with CSS error | Tailwind syntax (e.g., `dark: !text-white`) | Remove space: `dark:!text-white` |
| API returns 0 Unknown Error | Backend not running | Start PHP server on port 8000 |
| Route shows 404 | Route not registered | Check app.route.ts and module routes |
| Sidebar menu not appearing | HTML syntax error | Check closing tags, accordion keys |
| Component not loading | Missing standalone:true | Add to @Component decorator |

### File Locations Quick Reference

```
ROUTING
├── Main Routes............ src/app/app.route.ts
├── Connectivity Routes.... src/app/connectivity/connectivity.routes.ts
├── Organization Routes.... src/app/organization/organization.routes.ts
├── CMS Admin Routes....... src/app/cms-admin/cms-admin.routes.ts
└── Logs Routes............ src/app/logs/logs.routes.ts

LAYOUT
├── Sidebar HTML........... src/app/layouts/sidebar.html
├── Sidebar TS............. src/app/layouts/sidebar.ts
├── Header................. src/app/layouts/header.html
└── App Layout............. src/app/layouts/app-layout.html

STYLING
├── Tailwind Config........ tailwind.config.js
├── Main CSS............... src/assets/css/app.css
├── Tailwind Custom........ src/assets/css/tailwind.css
├── Color Themes........... src/assets/css/color-themes.css
└── Form Elements.......... src/assets/css/form-elements.css

SHARED COMPONENTS
├── Not Available Page..... src/app/shared/na/na.ts
├── Icons.................. src/app/shared/icon/
└── Animations............. src/app/shared/animations.ts
```

### Development Commands

```bash
# Start Angular dev server
npm start

# Start PHP API server (WAMP64)
C:\wamp64\bin\php\php8.4.15\php.exe -S localhost:8000 api.php

# Build for production
npm run build

# Clear Angular cache (if zombie file issues)
Remove-Item -Recurse -Force .angular
```

### Component Template Pattern

```typescript
import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { Store } from '@ngrx/store';
import { environment } from '../../environments/environment';

@Component({
    templateUrl: './[component-name].html',
    imports: [CommonModule],
    standalone: true
})
export class [ComponentName]Component implements OnInit {
    store: any;
    isLoading = true;
    data: any[] = [];
    private http = inject(HttpClient);

    constructor(public storeData: Store<any>) {
        this.initStore();
    }

    async initStore() {
        this.storeData.select((d) => d.index).subscribe((d) => {
            this.store = d;
        });
    }

    ngOnInit() {
        this.loadData();
    }

    loadData() {
        this.isLoading = true;
        this.http.get<any>(`${environment.apiUrl}/v1/[endpoint]`).subscribe({
            next: (response) => {
                this.data = response.data || [];
                this.isLoading = false;
            },
            error: (error) => {
                console.error('Failed to load:', error);
                this.isLoading = false;
            }
        });
    }
}
```

---

**Remember:**
- Always use `standalone: true` in components
- API runs on port 8000, Angular on port 4200
- Default theme is DARK mode
- Check `environment.ts` for API URL config
- NAComponent is the placeholder for unfinished pages

---

## Deployment

### Quick Deploy (Recommended)

Use the workflow command `/deploy` which auto-runs all deploy steps without approval.

**Workflow file:** `.agent/workflows/deploy.md`

### Using deploy.sh Script

After building and creating tar, run the deploy script:

```bash
# 1. Build Angular
npm run build

# 2. Create tar (skip images folder)
tar -czvf deploy.tar.gz -C dist . --exclude="assets/images"

# 3. Run deploy script (uploads & extracts on server)
bash .agent/workflows/deploy.sh
```

**Script file:** `.agent/workflows/deploy.sh`

### Manual Deploy Steps

1. **Build Angular project:**
   ```bash
   npm run build
   ```

2. **Create tar archive (skip images):**
   ```bash
   tar -czvf deploy.tar.gz -C dist . --exclude="assets/images"
   ```

3. **Upload to server:**
   ```bash
   scp deploy.tar.gz root@103.154.80.171:/var/www/html/SmartCMS-Visto/
   ```

4. **Extract on server:**
   ```bash
   ssh root@103.154.80.171 "cd /var/www/html/SmartCMS-Visto/ && tar -xzf deploy.tar.gz && rm deploy.tar.gz && chown -R www-data:www-data ."
   ```

### Server Info
- **Server:** 103.154.80.171
- **Path:** /var/www/html/SmartCMS-Visto/
- **URL:** http://103.154.80.171/SmartCMS/
