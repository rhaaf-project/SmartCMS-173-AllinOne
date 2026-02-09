#!/bin/bash
pkill -f 'php.*8000' 2>/dev/null || true
cd /var/www/SmartCMS-173
nohup php -S 127.0.0.1:8000 api.php > /var/log/smartcms-api.log 2>&1 &
sleep 2
echo "PHP server status:"
ss -tlnp | grep 8000
echo "Test login:"
curl -s -X POST http://127.0.0.1:8000/api/v1/login -H 'Content-Type: application/json' -d '{"email":"superadmin@smartcms.local","password":"SmartCMS@2026"}'
