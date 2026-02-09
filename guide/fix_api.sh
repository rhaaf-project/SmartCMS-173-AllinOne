#!/bin/bash
# Fix api.php database connection for MariaDB socket auth
sed -i "s/\$host = '127.0.0.1';/\$host = 'localhost';/" /var/www/SmartCMS-173/api.php
echo "API host changed to localhost"

# Also try adding socket fallback - append after password line
grep -q 'unix_socket' /var/www/SmartCMS-173/api.php || sed -i "/\$password = '';/a\$socket = '/run/mysqld/mysqld.sock';" /var/www/SmartCMS-173/api.php

# Test login
curl -s -X POST http://localhost/api/v1/login -H 'Content-Type: application/json' -d '{"email":"superadmin@smartcms.local","password":"SmartCMS@2026"}'
