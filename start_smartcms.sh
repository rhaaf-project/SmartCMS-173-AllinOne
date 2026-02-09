#!/bin/bash
# SmartCMS 173 Startup Script
# Run: ./start_smartcms.sh

echo "=== Starting SmartCMS on Server 173 ==="

# Kill existing PHP API if running
pkill -f 'php.*8000' 2>/dev/null || true

# Start PHP API server
cd /var/www/SmartCMS-173
nohup php -S 127.0.0.1:8000 api.php > /var/log/smartcms-api.log 2>&1 &
sleep 2

# Verify
echo "PHP API Status:"
ss -tlnp | grep 8000

echo ""
echo "Nginx Status:"
systemctl status nginx --no-pager | head -3

echo ""
echo "MariaDB Status:"
systemctl status mariadb --no-pager | head -3

echo ""
echo "=== SmartCMS Ready ==="
echo "URL: http://103.154.80.173/"
echo "Login: superadmin@smartcms.local / SmartCMS@2026"
