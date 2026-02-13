---
description: Deploy SmartCMS to server 173 (all-in-one) with correct DB credentials. ⚠️ api.php sbc-status uses docker exec (NOT AMI). See guide/SBC_STATUS_MONITOR_DEPLOY.md
---

# Deploy to Server 173

> [!CAUTION]
> Server 173 uses **different DB credentials** than local dev.
> Local: `root` / (empty)
> Server 173: `asterisk` / `Maja1234!`
> Every time you upload a fresh `api.php` to 173, you MUST patch the credentials.

## Steps

1. Upload source files to 173:
```
scp <files> root@103.154.80.173:/var/www/SmartCMS-173/src/app/...
scp api.php root@103.154.80.173:/var/www/SmartCMS-173/
```

2. **Fix DB credentials** (required after uploading api.php):
```
scp fix_db_creds.py root@103.154.80.173:/tmp/
ssh root@103.154.80.173 "python3 /tmp/fix_db_creds.py"
```

3. Build on server:
// turbo
```
ssh root@103.154.80.173 "cd /var/www/SmartCMS-173 && npm run build 2>&1 | tail -5"
```

4. Fix baseHref (production uses `/` not `/SmartCMS/`):
// turbo
```
ssh root@103.154.80.173 "sed -i 's|/SmartCMS/|/|g' /var/www/SmartCMS-173/dist/index.html"
```

5. Reload nginx:
// turbo
```
ssh root@103.154.80.173 "nginx -s reload"
```

6. Restart PHP API server:
```
ssh root@103.154.80.173 "fuser -k 8000/tcp 2>/dev/null; cd /var/www/SmartCMS-173 && nohup php -S 127.0.0.1:8000 api.php > /tmp/api_php.log 2>&1 &"
```

7. Verify API works:
// turbo
```
ssh root@103.154.80.173 "curl -s http://127.0.0.1:8000/api/v1/sbcs | head -c 200"
```

## PowerShell Escaping Notes
- Avoid inline `sed` with `$` variables via SSH from PowerShell — `$` gets interpolated
- Use Python scripts (upload via scp, then exec) for text replacement on remote server
- For simple commands, single-quote the SSH command: `ssh user@host 'command'`
