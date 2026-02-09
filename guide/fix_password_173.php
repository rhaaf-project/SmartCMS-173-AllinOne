<?php
$pdo = new PDO('mysql:host=127.0.0.1;dbname=db_ucx', 'root', '');
$hash = password_hash('SmartCMS@2026', PASSWORD_BCRYPT);
$stmt = $pdo->prepare('UPDATE users SET password=? WHERE email=?');
$stmt->execute([$hash, 'superadmin@smartcms.local']);
echo "Password reset for superadmin@smartcms.local\n";
echo "New hash: $hash\n";

// Also reset other common users
$stmt->execute([$hash, 'root@smartcms.local']);
echo "Password reset for root@smartcms.local\n";

$stmt->execute([$hash, 'cmsadmin@smartx.local']);
echo "Password reset for cmsadmin@smartx.local\n";

echo "\nAll passwords set to: SmartCMS@2026\n";
?>