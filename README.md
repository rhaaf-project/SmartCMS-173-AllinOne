# SmartCMS 173 All-in-One

**Server:** 103.154.80.173  
**Purpose:** Demo server with CMS, PBX, and Turret combined

---

## Repo Structure

```
SmartCMS-173-AllinOne/
├── cms/           # Angular CMS (source + API)
├── pbx/           # Docker Asterisk configs
├── turret/        # Ionic Turret App
├── docker-compose.yml
└── README.md
```

---

## Server Paths

| Component | Path | Description |
|-----------|------|-------------|
| CMS Angular | `/var/www/SmartCMS-173/` | dist + api.php |
| CMS Source | `/var/www/SmartCMS-173/src/` | Angular source |
| PBX Docker | `/opt/smartcms/asterisk/` | Dockerfile, configs |
| Turret | `/var/www/turret/` | Ionic app |
| Docker Compose | `/opt/smartcms/docker-compose.yml` | Main compose |

---

## Quick Start

```bash
# Start all services
cd /opt/smartcms
docker-compose up -d

# Start CMS API
cd /var/www/SmartCMS-173
./start_smartcms.sh
```

---

## Login Credentials

| Email | Password |
|-------|----------|
| root@smartcms.local | Maja1234 |
| superadmin@smartcms.local | SmartCMS@2026 |

---

## URLs

- **CMS:** http://103.154.80.173/
- **Turret:** TBD (requires setup)
- **PBX:** Internal Docker network

---

*Last updated: 2026-02-10*
