# ⚠️ SBC STATUS MONITOR — CRITICAL DEPLOYMENT GUIDE

> **READ THIS BEFORE TOUCHING `api.php` sbc-status ENDPOINT OR DEPLOYING!**

## Architecture: TWO DIFFERENT ENVIRONMENTS

```
┌─────────────────────────────────────────────────────────────┐
│  171 + 172 (SEPARATED)                                      │
│                                                             │
│  171 (CMS + MariaDB)  ──── AMI TCP:5038 ────▶  172 (PBX)   │
│                                                             │
│  api.php uses: fsockopen() to AMI on 172                    │
│  Repo: SmartCMS-Angular-171                                 │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  173 (ALL-IN-ONE)                                           │
│                                                             │
│  173 (CMS + MariaDB + PBX in Docker)                        │
│                                                             │
│  api.php uses: docker exec asterisk asterisk -rx "..."      │
│  Repo: SmartCMS-173-AllinOne                                │
└─────────────────────────────────────────────────────────────┘
```

## ❌ THE #1 MISTAKE TO AVOID

**NEVER copy `api.php` from one environment to the other without changing the `sbc-status` endpoint!**

The `sbc-status/{id}` endpoint in `api.php` is **DIFFERENT** between 171 and 173:

| File | 171 api.php | 173 api.php |
|------|------------|------------|
| **Method** | AMI via `fsockopen()` to PBX host:5038 | `exec('docker exec asterisk ...')` |
| **PBX location** | Remote server 172 | Local Docker container |
| **Endpoint code section** | `// SBC Status Monitor - Live PJSIP Channels via AMI` | `// SBC Status Monitor - Live PJSIP Channels endpoint` |

## ✅ WHAT IS SAFE TO COPY BETWEEN ENVIRONMENTS

| File | Same? | Notes |
|------|-------|-------|
| `src/app/connectivity/sbc-status-monitor.html` | ✅ YES | UI is identical |
| `src/app/connectivity/sbc-status-monitor.ts` | ✅ YES | Frontend logic identical |
| `api.php` (sbc-status section) | ❌ **NO** | **DIFFERENT per environment** |
| `api.php` (everything else) | ✅ YES | Same (but fix DB creds on 173) |

## 173 Extra Steps After Deploying api.php

1. **Fix DB credentials**: local uses `root/''`, server 173 uses `asterisk/Maja1234!`
2. Use `fix_db_creds.py` script (scp + run via python3)
3. Restart PHP server: `fuser -k 8000/tcp; nohup php -S 127.0.0.1:8000 api.php &`

## AMI Credentials (171→172)

- Host: from `call_servers` table `host` column
- Port: 5038
- Username: `admin`
- Password: `admin`
- These may need updating if PBX AMI config changes
