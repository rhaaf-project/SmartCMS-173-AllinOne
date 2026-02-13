# SBC STATUS MONITOR — DEPLOYMENT GUIDE

> **READ THIS BEFORE TOUCHING `api.php` sbc-status ENDPOINT OR DEPLOYING!**

## Architecture: UNIFIED AMI APPROACH

Both environments use the **same** `api.php` code for SBC Status Monitor.
The `sbc-status/{id}` endpoint connects to Asterisk via **AMI (fsockopen)** on port **5038**.

```
┌─────────────────────────────────────────────────────────────┐
│  171 + 172 (SEPARATED)                                      │
│  CMS (171) ──── AMI TCP:5038 ────▶ PBX (172)                │
│  PBX host: from call_servers table                          │
│  Repo: SmartCMS-Angular-171                                 │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  173 (ALL-IN-ONE)                                           │
│  CMS ──── AMI TCP:5038 ────▶ PBX (Docker, host network)    │
│  PBX host: from call_servers table (127.0.0.1 or localhost) │
│  Repo: SmartCMS-173-AllinOne                                │
└─────────────────────────────────────────────────────────────┘
```

## ✅ api.php sbc-status IS NOW IDENTICAL ON BOTH ENVIRONMENTS

| File | Same across 171 & 173? |
|------|----------------------|
| `api.php` sbc-status section | ✅ YES — both use AMI |
| `sbc-status-monitor.html` | ✅ YES |
| `sbc-status-monitor.ts` | ✅ YES |
| `api.php` DB credentials | ❌ NO — 171 uses `root/''`, 173 uses `asterisk/Maja1234!` |

## AMI Credentials

- Port: **5038**
- Username: **admin**
- Password: **admin1234**
- Config file: `/etc/asterisk/manager.conf` (inside Docker on 173)

## 173 Extra Steps After Deploying api.php

> [!CAUTION]
> When uploading api.php to 173, you MUST fix DB credentials afterwards:

1. Upload `fix_db_creds.py` and run it (changes `root/''` → `asterisk/Maja1234!`)
2. Restart PHP server: `fuser -k 8000/tcp; nohup php -S 127.0.0.1:8000 api.php &`

## Call Server Host Configuration

The sbc-status endpoint reads the PBX host from the `call_servers` table.
Make sure the call_server entry has the correct host:

| Environment | call_servers.host should be |
|------------|---------------------------|
| 171→172 | `103.154.80.172` (PBX IP) |
| 173 | `127.0.0.1` or `localhost` |
