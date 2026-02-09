---
description: Start local PHP development server using WAMP
---

# Start Local PHP Server

Start PHP development server for SmartCMS API on localhost:8000.

// turbo-all

## Steps

1. Start PHP server (WAMP) with router file
```powershell
& "C:\wamp64\bin\php\php8.2.29\php.exe" -S localhost:8000 api.php
```

> **IMPORTANT:** The `api.php` at the end is required! Without it, API routes will return 404.

## Environment Info

### WAMP Paths
- **PHP**: `C:\wamp64\bin\php\php8.2.29\php.exe`
- **MySQL Client**: `C:\wamp64\bin\mysql\mysql8.4.7\bin\mysql.exe`
- **Available PHP versions**: php8.0.30, php8.1.33, php8.2.29, php8.3.28, php8.4.15, php8.5.0

### Servers
- **Local API**: http://localhost:8000
- **Angular Dev**: http://localhost:4200
- **Production**: 103.154.80.171

### Database
- **Local DB**: db_ucx (MariaDB, user: root, no password)
