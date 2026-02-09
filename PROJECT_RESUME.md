# SmartCMS VISTO - Project Resume

## Project Overview

**Project Name:** SmartCMS VISTO (Angular)  
**Framework:** Angular 20.3.10 dengan Standalone Components  
**Backend:** PHP API (api.php) + MariaDB  
**Repository:** `https://github.com/rhaaf-project/SmartCMS-Angular-171.git`

### Purpose
SmartCMS adalah **CMS (Call Management System)** untuk mengelola sistem PBX/Telekomunikasi. Sistem ini menangani:
- **Organisasi**: Struktur perusahaan (Company, Head Office, Branch, Sub Branch)
- **Connectivity**: Konfigurasi call server, extension, trunk, SBC, routing
- **Features**: IVR, Ring Group, Recording, Time Conditions, Conference
- **Turret Management**: Manajemen turret users, groups, templates, policies
- **Network**: Static Route, Firewall
- **Logs**: Activity logs, Call logs, System logs

---

## Project Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      SmartCMS VISTO                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌─────────────────┐       ┌─────────────────┐                │
│   │  Angular SPA    │──────▶│   PHP API       │                │
│   │  (Port 4200)    │       │  (api.php)      │                │
│   └─────────────────┘       └────────┬────────┘                │
│                                      │                          │
│                                      ▼                          │
│                             ┌─────────────────┐                │
│                             │   MariaDB       │                │
│                             │   (db_ucx)      │                │
│                             └─────────────────┘                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Key Technologies
| Layer | Technology | Version |
|-------|------------|---------|
| Frontend | Angular | 20.3.10 |
| State | NgRx Store | - |
| Styling | Tailwind CSS | - |
| Template | VRISTO Admin | - |
| Backend | PHP (Native API) | 8.2+ |
| Database | MariaDB | 11.8.3 |

---

## Folder Structure

```
CMS/
├── src/
│   ├── app/
│   │   ├── layouts/          # Header, Sidebar, Footer
│   │   ├── auth/             # Login (boxed-signin)
│   │   ├── organization/     # Company, HO, Branch, Sub Branch
│   │   ├── connectivity/     # Extensions, Trunk, IVR, Routing
│   │   ├── turret-management/# Turret Users, Groups, Policies
│   │   ├── network/          # Static Route, Firewall
│   │   ├── logs/             # Activity, Call, System Logs
│   │   └── cms-admin/        # CMS Users, Layout Customizer
│   ├── assets/
│   │   ├── css/              # Tailwind, Modal styles
│   │   └── images/           # Flags, Icons
│   └── environments/         # API URL config
├── api.php                   # Backend API (single file)
├── DEPLOYMENT_GUIDE.md       # Panduan deploy ke server
├── ANGULAR_NEW_PAGE_GUIDE.md # Panduan buat page baru
├── db_erd.md                 # Database ERD
└── dist/                     # Build output
```

---

## Database Structure (db_ucx)

### Core Tables
| Table | Description |
|-------|-------------|
| `customers` | Data perusahaan/client |
| `head_offices` | Kantor pusat regional |
| `branches` | Branch/cabang |
| `sub_branches` | Sub-cabang |
| `call_servers` | PBX server configuration |
| `extensions` | Internal phone extensions |
| `trunks` | External line connections |
| `sbcs/sbc_connections/sbc_routings` | SBC configuration |
| `ivr/ivr_entries` | Interactive Voice Response |
| `inbound_routings/outbound_routings` | Call routing rules |
| `users` | CMS login users |
| `activity_logs` | User activity audit trail |

### Database Diagram (ERD)
See: [db_erd.md](db_erd.md)

---

## Quick Start

### Local Development

```powershell
# 1. Start MariaDB (via WAMP)
# Database: db_ucx

# 2. Start PHP API Server
cd D:\02____WORKS\04___Server\Projects\CMS\VISTO\CMS
& "C:\wamp64\bin\php\php8.2.29\php.exe" -S localhost:8000 api.php

# 3. Start Angular Dev Server
npm run start
# Open: http://localhost:4200
```

### Login Credentials
| Email | Password | Role |
|-------|----------|------|
| `root@smartcms.local` | `Maja1234` | superadmin |
| `cmsadmin@smartx.local` | `Admin@123` | admin |
| `admin@smartx.local` | `admin123` | admin |

---

## Server Information

### Production Server
| Item | Value |
|------|-------|
| IP | `103.154.80.171` |
| URL | http://103.154.80.171/SmartCMS/ |
| SSH | `ssh root@103.154.80.171` |
| Web Path | `/var/www/html/SmartCMS-Visto/` |
| Database | MariaDB `db_ucx` |
| Nginx Port | 8082 |

### Server List
| IP | Purpose |
|----|---------|
| 103.154.80.171 | CMS + Database (Deploy Here) |
| 103.154.80.165 | PBX Production (Reference Only) |
| 103.154.80.170 | Turret App |
| 103.154.80.172 | PBX Server |

---

## Documentation Files

| File | Description |
|------|-------------|
| [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) | Panduan lengkap deploy ke server |
| [ANGULAR_NEW_PAGE_GUIDE.md](ANGULAR_NEW_PAGE_GUIDE.md) | Cara buat page/component baru |
| [db_erd.md](db_erd.md) | Database ERD diagram |
| [firewall_static.md](firewall_static.md) | Network security config |

---

## Common Workflows

### Deploy to Server
```bash
# Build Angular
npm run build

# Upload to server
scp -r dist/* root@103.154.80.171:/var/www/html/SmartCMS-Visto/
scp api.php root@103.154.80.171:/var/www/html/SmartCMS-Visto/

# Set permissions
ssh root@103.154.80.171 "chown -R www-data:www-data /var/www/html/SmartCMS-Visto"
```

### Sync Database
```powershell
# Dump local
C:\wamp64\bin\mysql\mysql8.4.7\bin\mysqldump.exe -u root db_ucx --result-file=db_ucx_clean.sql

# Upload and import
scp db_ucx_clean.sql root@103.154.80.171:/root/
ssh root@103.154.80.171 "mysql -u root db_ucx < /root/db_ucx_clean.sql"
```

### Create New Page
1. Create component: `src/app/[module]/[name].ts`
2. Create template: `src/app/[module]/[name].html`
3. Add route to module routes file
4. Add to sidebar: `src/app/layouts/sidebar.html`

See: [ANGULAR_NEW_PAGE_GUIDE.md](ANGULAR_NEW_PAGE_GUIDE.md)

---

## Agent Slash Commands

| Command | Description |
|---------|-------------|
| `/deploy` | Build & deploy ke server 171 |
| `/migrate` | Run SQL migrations di local |
| `/local-server` | Start local dev servers |

---

## Design Guidelines

### Modal Styling
- Header background: `bg-[#1a2941]`
- Header text: `text-white`
- Panel: `!p-0` with separate body `p-5`
- Close button: `text-gray-400 hover:text-white`

### Table Active Column
- Use `icon-circle-check` component
- Center alignment: `text-align: -webkit-center`

### CSS Files
- `src/assets/css/modal.css` - Modal glow & scrollbar
- `src/assets/css/tailwind.css` - Main Tailwind imports

---

## Important Notes

1. **JANGAN CAMPUR REPO!**
   - Angular: `SmartCMS-Angular-171.git` (MariaDB)
   - Filament: `SmartCMS-Postgre-171.git` (PostgreSQL)

2. **API Server Required**
   - Login & semua data butuh API running
   - Jalankan: `php -S localhost:8000 api.php`

3. **Database Name**
   - Local & Server sama: `db_ucx`

4. **Standalone Components**
   - Semua component pakai `standalone: true`
   - Import modules langsung di `@Component({ imports: [...] })`

---

*Last Updated: 2026-02-05*
