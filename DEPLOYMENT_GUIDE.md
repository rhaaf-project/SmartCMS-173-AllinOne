# SmartCMS Deployment Guide

**Project:** SmartCMS Angular  
**Last Updated:** 2026-02-03

---

## 🤖 Agent Workflow Commands (Slash Commands)

| Command | Description | Auto-Run |
|---------|-------------|----------|
| `/deploy` | Build Angular + upload ke server 103.154.80.171 | ✅ Yes |
| `/migrate` | Run SQL migrations di local db_ucx | ✅ Yes |
| `log session` | Update usage log dengan timestamp & activity | Manual |

> [!TIP]
> - Ketik `/deploy` atau `/migrate` untuk workflow tanpa approve
> - Bilang **"log session"** di awal/akhir coding untuk track usage
> - Check log: `C:\Users\Fajar\.gemini\antigravity\brain\[session-id]\usage_log.md`

---

## Server List

| IP | Purpose | Notes |
|----|---------|-------|
| `103.154.80.165` | **PBX Production** | ⚠️ REFERENCE STRUKTUR TABLE ONLY - JANGAN DIRUSAK |
| `103.154.80.170` | Turret App | - |
| `103.154.80.171` | **CMS + Database** | ✅ Deploy here |
| `103.154.80.172` | PBX Server | - |


## ⚠️ IMPORTANT - Project Separation

| Project | Repo | Server | DB Engine | DB Name |
|---------|------|--------|-----------|---------|
| **SmartCMS Angular** | `SmartCMS-Angular-171.git` | 103.154.80.**171** | **MariaDB** | `smartucx_db` (server) / `db_ucx` (local) |
| SmartCMS Postgre | `SmartCMS-Postgre-171.git` | - | PostgreSQL | berbeda! |

> [!CAUTION]
> **JANGAN CAMPUR!** Angular pakai MariaDB, Filament pakai PostgreSQL.
> - Syntax SQL berbeda
> - Repo berbeda
> - Salah pilih = ERROR / Data corrupt

> [!WARNING]
> **Sebelum deploy, SELALU cek:**
> ```bash
> git remote -v
> # HARUS: SmartCMS-Angular-171.git
> # BUKAN: SmartCMS-Postgre-171.git
> ```

### Database Names - JANGAN SALAH!

| Environment | Database Name | Engine | Command |
|-------------|---------------|--------|---------|
| **Local (WAMP)** | `db_ucx` | MariaDB 8.4.7 | `mysql -u root db_ucx` |
| **Server 171** | `db_ucx` | MariaDB 11.8.3 | `mysql -u root db_ucx` |
| Postgre Project | *jangan sentuh* | PostgreSQL | *jangan pakai* |

> [!NOTE]  
> Database name sama di local dan server = `db_ucx`. Lebih simple!


---

## Server Info (Angular VISTO)

| Item | Value |
|------|-------|
| **IP** | `103.154.80.171` |
| **SSH** | `ssh root@103.154.80.171` |
| **Web Path** | `/var/www/html/SmartCMS-Visto/` |
| **URL** | http://103.154.80.171/SmartCMS/ |
| **Database** | MariaDB 11.8.3 |
| **DB Name** | `db_ucx` |
| **Nginx Port** | 8082 (proxied from /SmartCMS/) |

---

## 🔧 Nginx Reconfiguration (2026-01-31)

### Issue
`/SmartCMS/` was pointing to **old Laravel app** (SmartCMS_App on port 8080) instead of **Angular VISTO**.

### Root Cause
- Nginx config proxied `/SmartCMS/` → `http://127.0.0.1:8080` (Laravel)
- Angular VISTO files tidak pernah di-deploy ke server
- Database `smartucx_db` masih berisi data lama (Smart Infinite Prosperity)

### Solution
1. **Upload Angular dist** → `/var/www/html/SmartCMS-Visto/`
2. **Copy api.php** → ke folder SmartCMS-Visto
3. **Update nginx** → `/SmartCMS/` proxy ke port **8082** (bukan 8080)
4. **Create db_ucx** on server → sama dengan local database name
5. **Import local dump** → sync data dari local ke server

### Nginx Config Changes

**Before (WRONG):**
```nginx
location ^~ /SmartCMS/ {
    proxy_pass http://127.0.0.1:8080;  # OLD Laravel app
}
```

**After (CORRECT):**
```nginx
# Port 8082 - Angular VISTO
server {
    listen 8082;
    root /var/www/html/SmartCMS-Visto;
    
    location = /api.php {
        fastcgi_pass unix:/run/php/php8.4-fpm.sock;
    }
    
    location /api/ {
        rewrite ^(.*)$ /api.php last;
    }
    
    location / {
        try_files $uri $uri/ /index.html;
    }
}

# Port 80 - Main proxy
location ^~ /SmartCMS/ {
    proxy_pass http://127.0.0.1:8082;  # NEW Angular VISTO
}
```

### Files Changed
- `/etc/nginx/sites-available/default` - Added port 8082, changed proxy 8080→8082
- `/var/www/html/SmartCMS-Visto/api.php` - Uses `db_ucx` database

## Local Development

| Item | Value |
|------|-------|
| **Path** | `D:\02____WORKS\04___Server\Projects\CMS\VISTO\CMS` |
| **Repo** | `https://github.com/rhaaf-project/SmartCMS-Angular-171.git` |
| **Dev Server** | `npm run start` → http://localhost:4200 |
| **API Server** | `php -S localhost:8000 api.php` |
| **Local DB** | MariaDB `db_ucx` (WAMP64) |

---

## Commit & Push

```bash
# 1. Check what changed
git status --short

# 2. Add files (EXCLUDE public folder if too large)
git add src/ api.php
# OR add specific files:
git add src/app/organization/head-office/*.ts src/app/organization/head-office/*.html

# 3. Commit with descriptive message
git commit -m "feat: Description of changes"

# 4. Push to Angular repo
git push origin main
```

---

## Deploy to Server

```bash
# 1. SSH to server
ssh root@103.154.80.171

# 2. Go to SmartCMS folder
cd /var/www/html/SmartCMS

# 3. Verify remote is Angular (NOT Postgre!)
git remote -v
# Should show: SmartCMS-Angular-171.git

# 4. Pull latest
git pull origin main

# 5. Exit
exit
```

---

## Database Migrations

**Local (WAMP - db_ucx):**
```bash
C:\wamp64\bin\mysql\mysql8.4.7\bin\mysql.exe -u root db_ucx -e "ALTER TABLE ..."
```

**Server (smartucx_db):**
```bash
ssh root@103.154.80.171 "mysql -u root smartucx_db -e 'ALTER TABLE ...'"
```

### Recent Migrations (2026-01-30)
```sql
-- head_offices: Call Servers HA/FO + BCP/DRC
ALTER TABLE head_offices 
  ADD COLUMN bcp_drc_server_id INT NULL,
  ADD COLUMN bcp_drc_enabled TINYINT(1) DEFAULT 0,
  ADD COLUMN call_servers_json TEXT NULL;

-- sub_branches: Call Server
ALTER TABLE sub_branches 
  ADD COLUMN call_server_id INT NULL;
```

---

## Verification Checklist

After deploy, verify:
- [ ] `git remote -v` shows `SmartCMS-Angular-171.git`
- [ ] Website loads: http://103.154.80.171/SmartCMS/
- [ ] Database columns exist (check via phpMyAdmin or mysql CLI)
- [ ] New features work (test in browser)

---

## Quick Commands

```bash
# Full deploy (one-liner from Windows)
ssh root@103.154.80.171 "cd /var/www/html/SmartCMS-Visto && git pull origin main"

# Check server database
ssh root@103.154.80.171 "mysql -u root db_ucx -e 'SHOW TABLES;'"

# Check table structure
ssh root@103.154.80.171 "mysql -u root db_ucx -e 'DESCRIBE head_offices;'"
```

---

## 📦 Sync Local → Server (Files + Database)

### Step 1: Build Angular Locally
```bash
cd D:\02____WORKS\04___Server\Projects\CMS\VISTO\CMS
npm run build
```

### Step 2: Upload Built Files to Server
```bash
# Upload dist folder
scp -r dist/* root@103.154.80.171:/var/www/html/SmartCMS-Visto/

# OPTIMIZATION: Skip upload of static assets that rarely change (e.g. flags) to speed up
# rsync -av --exclude='assets/flags' dist/ root@103.154.80.171:/var/www/html/SmartCMS-Visto/

# Upload api.php if changed
scp api.php root@103.154.80.171:/var/www/html/SmartCMS-Visto/

# Set correct ownership
ssh root@103.154.80.171 "chown -R www-data:www-data /var/www/html/SmartCMS-Visto"
```

### Step 3: Sync Database
```bash
# 1. Dump local database (using --result-file to avoid encoding issues)
C:\wamp64\bin\mysql\mysql8.4.7\bin\mysqldump.exe -u root db_ucx --result-file=db_ucx_clean.sql --skip-extended-insert

# 2. Upload to server
scp db_ucx_clean.sql root@103.154.80.171:/root/

# 3. Import on server (with FK checks disabled)
ssh root@103.154.80.171 "mysql -u root db_ucx -e 'SET FOREIGN_KEY_CHECKS=0;' && mysql -u root db_ucx < /root/db_ucx_clean.sql && mysql -u root db_ucx -e 'SET FOREIGN_KEY_CHECKS=1;'"

# 4. Verify data
ssh root@103.154.80.171 "mysql -u root db_ucx -e 'SELECT COUNT(*) FROM customers; SELECT COUNT(*) FROM branches;'"
```

> [!IMPORTANT]
> **Encoding Issues?** Jika import gagal dengan error "ASCII '\0'":
> - Gunakan `--result-file=` bukan `>` redirect
> - Jalankan `sed -i 's/\r$//' file.sql` di server sebelum import
> - Disable FK checks: `SET FOREIGN_KEY_CHECKS=0;`

### Step 4: Verify Website
```bash
# Test API
curl http://103.154.80.171/SmartCMS/api/v1/branches

# Buka browser
http://103.154.80.171/SmartCMS/
```

---

## 🆕 Adding New Project with Separate Folder

### Port Allocation (Server 171)

| Port | Project | Path |
|------|---------|------|
| 80 | Main (Filament/smartX) | `/var/www/html/smartX/public` |
| 8080 | SmartCMS_App (Laravel lama) | `/var/www/html/SmartCMS_App/public` |
| 8082 | **SmartCMS-Visto (Angular)** | `/var/www/html/SmartCMS-Visto` |
| 8083 | *Reserved for next project* | - |
| 8084 | *Reserved* | - |

### Template: Add New Angular Project

**1. Create folder on server:**
```bash
ssh root@103.154.80.171 "mkdir -p /var/www/html/NewProject && chown www-data:www-data /var/www/html/NewProject"
```

**2. Upload files:**
```bash
scp -r dist/* root@103.154.80.171:/var/www/html/NewProject/
scp api.php root@103.154.80.171:/var/www/html/NewProject/
```

**3. Add nginx server block** (append to `/etc/nginx/sites-available/default`):
```nginx
# NewProject on port 8083
server {
    listen 8083;
    server_name _;

    root /var/www/html/NewProject;
    index index.html;

    # API - PHP handling
    location = /api.php {
        include fastcgi_params;
        fastcgi_pass unix:/run/php/php8.4-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root/api.php;
    }

    location /api/ {
        rewrite ^(.*)$ /api.php last;
    }

    # Angular SPA
    location / {
        try_files $uri $uri/ /index.html;
    }

    location ~ /\. {
        deny all;
    }
}
```

**4. Add proxy in port 80 server block:**
```nginx
# Add inside server { listen 80; ... }
location ^~ /NewProject/ {
    rewrite ^/NewProject/(.*)$ /$1 break;
    proxy_pass http://127.0.0.1:8083;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}

location = /NewProject {
    return 301 /NewProject/;
}
```

**5. Test and reload nginx:**
```bash
ssh root@103.154.80.171 "nginx -t && systemctl reload nginx"
```

**6. Create database (if needed):**
```bash
ssh root@103.154.80.171 "mysql -u root -e 'CREATE DATABASE IF NOT EXISTS new_project_db;'"
```

> [!CAUTION]
> **Sebelum deploy project baru:**
> - Pastikan port belum dipakai: `ss -tlnp | grep 808`
> - Folder name UNIK, jangan sama dengan existing
> - Update `api.php` dengan database name yang benar
> - Test nginx config SEBELUM reload: `nginx -t`

---

## 🔍 Troubleshooting

### Local API CORS Error / 404 Not Found (COMMON!)

**Symptoms:**
- Browser console: `CORS policy: No 'Access-Control-Allow-Origin' header`
- Browser console: `net::ERR_CONNECTION_REFUSED` or `net::ERR_FAILED`
- PHP server log: `[404]: GET /api/v1/xxx - No such file or directory`

**Cause:** 
PHP built-in server dijalankan **tanpa router file**, sehingga request ke `/api/v1/...` tidak diteruskan ke `api.php`.

**Solution:**
```powershell
# ❌ WRONG - Akan return 404 untuk semua API calls
& "C:\wamp64\bin\php\php8.2.29\php.exe" -S localhost:8000

# ✅ CORRECT - api.php sebagai router
& "C:\wamp64\bin\php\php8.2.29\php.exe" -S localhost:8000 api.php
                                                          ↑ WAJIB!
```

> [!IMPORTANT]
> File `api.php` di akhir command adalah **ROUTER FILE**. 
> Tanpanya, PHP server tidak tahu cara memproses `/api/v1/xxx` requests.

**Quick Check:**
```powershell
# Test API langsung
Invoke-WebRequest -Uri "http://localhost:8000/api/v1/turret-policies" -UseBasicParsing
# Harus return JSON data, bukan error
```

### API Returns Raw PHP Code
- **Cause:** Nginx tidak memproses PHP via fastcgi
- **Fix:** Pastikan location block `/api/` me-rewrite ke `/api.php` dan ada `location = /api.php` dengan fastcgi_pass

### Data Tidak Muncul di Website
1. Cek database name di `api.php`: `$dbname = 'db_ucx';`
2. Cek nginx proxy port: harus match dengan server block
3. Clear cache: `ssh root@... "php artisan cache:clear"` (jika Laravel)

### Nginx Config Error
```bash
# Test config syntax
nginx -t

# View error log
tail -50 /var/log/nginx/error.log

# Restore backup jika ada
cp /etc/nginx/sites-available/default.bak /etc/nginx/sites-available/default
```

### Database Import Error
- **"ASCII '\0'"**: File has BOM/encoding issue. Use `--result-file=` saat dump
- **"Foreign key constraint"**: Disable FK checks sebelum import
- **"Table exists"**: Drop tables dulu atau use `--add-drop-table` saat dump

---

## 🔧 PowerShell SSH Escaping Solutions

> [!CAUTION]
> PowerShell has different escaping rules than bash. Quotes, special chars (`$`, `@`, `!`) cause issues when running SSH commands from Windows.

### Problem
```powershell
# This FAILS - PowerShell interprets the quotes and special chars
ssh root@server "mysql -e \"SELECT * FROM users WHERE email='test@test.com'\""
```

### Solution 1: Base64 Encoding (RECOMMENDED)
```powershell
# Encode JSON payload as base64, decode on server
ssh root@103.154.80.171 "echo 'eyJlbWFpbCI6InJvb3RAc21hcnRjbXMubG9jYWwiLCJwYXNzd29yZCI6Ik1hamExMjM0In0=' | base64 -d > /tmp/data.json; curl -s -X POST http://127.0.0.1:8082/api/v1/login -H 'Content-Type: application/json' -d @/tmp/data.json"
```

### Solution 2: Create Script File Locally, Upload via SCP
```powershell
# 1. Create script file locally
# fix_passwords.php:
# <?php
# $pdo = new PDO('mysql:host=127.0.0.1;dbname=db_ucx', 'root', '');
# $hash = password_hash('Maja1234', PASSWORD_BCRYPT);
# $stmt = $pdo->prepare('UPDATE users SET password=? WHERE email=?');
# $stmt->execute([$hash, 'root@smartcms.local']);

# 2. Upload and run
scp fix_passwords.php root@103.154.80.171:/tmp/
ssh root@103.154.80.171 "php /tmp/fix_passwords.php"
```

### Solution 3: Heredoc with 'EOF' (Single Quotes)
```powershell
# Single-quoted EOF prevents variable expansion
ssh root@103.154.80.171 "cat > /tmp/script.sql << 'SQLEOF'
UPDATE users SET password='hash_value' WHERE email='test@test.com';
SQLEOF
mysql -u root db_ucx < /tmp/script.sql"
```

### Solution 4: Use chr() for Special Characters
```powershell
# Avoid special chars by using chr() codes
ssh root@103.154.80.171 "php -r 'echo password_hash(chr(77).chr(97).chr(106).chr(97).chr(49).chr(50).chr(51).chr(52), PASSWORD_BCRYPT);'"
# chr(77)=M, chr(97)=a, chr(106)=j, chr(97)=a, chr(49)=1, chr(50)=2, chr(51)=3, chr(52)=4 = "Maja1234"
```

### Characters to Avoid in PowerShell SSH
| Char | Issue | Workaround |
|------|-------|------------|
| `$` | Variable expansion | Escape `\$` or use single quotes |
| `@` | Splatting operator | Use base64 encoding |
| `"` | Quote nesting | Use heredoc or base64 |
| `!` | History expansion | Use single quotes |
| `&&` | Not valid in PS | Split into separate commands |

---

## 👤 User Management & Passwords

### Current Login System

> [!IMPORTANT]
> Login menggunakan **hardcoded credentials** di frontend (Angular), BUKAN API call ke database.
> Ini untuk simplicity dan menghindari dependency ke backend API.

### Valid Credentials (Hardcoded in Angular)
| Email | Password | Location |
|-------|----------|----------|
| root@smartcms.local | Maja1234 | `src/app/auth/boxed-signin.ts` |
| admin@smartx.local | admin123 | `src/app/auth/boxed-signin.ts` |
| cmsadmin@smartx.local | Admin@123 | `src/app/auth/boxed-signin.ts` |

### Adding New User

**Step 1: Update Angular (Frontend)**
```typescript
// File: src/app/auth/boxed-signin.ts
private validCredentials = [
    { email: 'root@smartcms.local', password: 'Maja1234' },
    { email: 'admin@smartx.local', password: 'admin123' },
    { email: 'cmsadmin@smartx.local', password: 'Admin@123' },
    { email: 'newuser@company.com', password: 'NewPass123' },  // ADD NEW USER
];
```

**Step 2: Update Database (Optional - only if API login is used)**
```powershell
# Create PHP script to add user with bcrypt hash
# File: add_user.php
<?php
$pdo = new PDO('mysql:host=127.0.0.1;dbname=db_ucx', 'root', '');
$hash = password_hash('NewPass123', PASSWORD_BCRYPT);
$stmt = $pdo->prepare('INSERT INTO users (name, email, password, created_at, updated_at) VALUES (?, ?, ?, NOW(), NOW())');
$stmt->execute(['New User', 'newuser@company.com', $hash]);
echo "User created!\n";

# Upload and run
scp add_user.php root@103.154.80.171:/tmp/
ssh root@103.154.80.171 "php /tmp/add_user.php"
```

**Step 3: Rebuild and Deploy**
```powershell
npm run build
scp -r dist/* root@103.154.80.171:/var/www/html/SmartCMS-Visto/
ssh root@103.154.80.171 "chown -R www-data:www-data /var/www/html/SmartCMS-Visto"
```

### Resetting Password

**Option A: Update Hardcoded Credentials (Frontend)**
```typescript
// Edit src/app/auth/boxed-signin.ts
// Change password value, rebuild, and deploy
```

**Option B: Update Database (For API-based login)**
```powershell
# Create reset script
# File: reset_password.php
<?php
$pdo = new PDO('mysql:host=127.0.0.1;dbname=db_ucx', 'root', '');
$hash = password_hash('NewPassword123', PASSWORD_BCRYPT);
$stmt = $pdo->prepare('UPDATE users SET password=? WHERE email=?');
$stmt->execute([$hash, 'user@email.com']);
echo "Password reset!\n";

# Upload and run
scp reset_password.php root@103.154.80.171:/tmp/
ssh root@103.154.80.171 "php /tmp/reset_password.php"
```

### Password Hash Format
- Algorithm: **bcrypt** (PASSWORD_BCRYPT in PHP)
- Format: `$2y$12$...` (60 characters)
- **NEVER** store plain text passwords in database

---

## 📋 Deployment Checklist

### Before Deploy
- [ ] `git remote -v` → confirm correct repo
- [ ] `npm run build` → no errors
- [ ] `api.php` → correct database name

### During Deploy
- [ ] Upload dist files
- [ ] Upload api.php
- [ ] Import database (if data changed)
- [ ] `chown -R www-data:www-data`

### After Deploy
- [ ] Test API: `curl .../api/v1/branches`
- [ ] Test website in browser
- [ ] Check data matches local
- [ ] Verify no console errors

---

*Last Updated: 2026-01-31*

