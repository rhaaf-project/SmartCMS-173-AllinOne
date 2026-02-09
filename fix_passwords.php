<?php
$pdo = new PDO('mysql:host=127.0.0.1;dbname=db_ucx', 'root', '');
$users = [
    ['root@smartcms.local', 'Maja1234'],
    ['admin@smartx.local', 'admin123'],
    ['cmsadmin@smartx.local', 'Admin@123']
];
foreach ($users as $u) {
    $hash = password_hash($u[1], PASSWORD_BCRYPT);
    $stmt = $pdo->prepare('UPDATE users SET password=? WHERE email=?');
    $stmt->execute([$hash, $u[0]]);
    echo "Updated " . $u[0] . " with hash: " . substr($hash, 0, 20) . "...\n";
}
echo "Done!\n";
