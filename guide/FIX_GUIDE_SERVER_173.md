# 🔧 Server 173 Fix Guide - FINAL

**Status:** ✅ FIXED & WORKING  
**URL:** http://103.154.80.173/  
**Login:** `superadmin@smartcms.local` / `SmartCMS@2026`

---

## Issues Fixed

| Issue | Root Cause | Solution |
|-------|------------|----------|
| Login failed | Password hash mismatch | Reset with correct bcrypt hash |
| API 404 | PHP server not using router | Restart with `php -S 127.0.0.1:8000 api.php` |

---

## Quick Commands

### Start CMS (if API down after reboot)
```bash
ssh root@103.154.80.173 "/var/www/SmartCMS-173/start_smartcms.sh"
```

### Reset Password
```bash
ssh root@103.154.80.173 "php /tmp/verify_and_fix.php"
```

### Check Status
```bash
ssh root@103.154.80.173 "ss -tlnp | grep 8000"
```

---

## Files on Server

| Path | Purpose |
|------|---------|
| `/var/www/SmartCMS-173/` | Angular dist + api.php |
| `/var/www/SmartCMS-173/start_smartcms.sh` | Startup script |
| `/tmp/verify_and_fix.php` | Password reset script |
| `/etc/nginx/sites-enabled/smartcms` | Nginx config |

---

## Credentials

| Email | Password |
|-------|----------|
| superadmin@smartcms.local | SmartCMS@2026 |
| root@smartcms.local | SmartCMS@2026 |
| cmsadmin@smartx.local | SmartCMS@2026 |
