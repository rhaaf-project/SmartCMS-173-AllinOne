<?php
// Sync passwords on server 173 to match local/171
$pdo = new PDO('mysql:unix_socket=/run/mysqld/mysqld.sock;dbname=db_ucx', 'root', '');

$users = [
    ['root@smartcms.local', 'Maja1234'],
    ['admin@smartx.local', 'admin123'],
    ['cmsadmin@smartx.local', 'Admin@123'],
    ['superadmin@smartcms.local', 'SmartCMS@2026'],
];

$stmt = $pdo->prepare('UPDATE users SET password=? WHERE email=?');

foreach ($users as $user) {
    $hash = password_hash($user[1], PASSWORD_BCRYPT);
    $stmt->execute([$hash, $user[0]]);
    echo "✓ {$user[0]} -> {$user[1]}\n";
}

echo "\nAll passwords synced!\n";
