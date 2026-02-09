<?php
try {
    $pdo = new PDO('mysql:host=127.0.0.1;dbname=db_ucx;charset=utf8mb4', 'root', '', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $stmt = $pdo->query('SELECT password FROM users WHERE email="superadmin@smartcms.local"');
    $hash = $stmt->fetchColumn();
    echo "Stored hash: $hash\n";
    echo "Length: " . strlen($hash) . "\n";
    echo "Verify SmartCMS@2026: " . (password_verify('SmartCMS@2026', $hash) ? 'MATCH!' : 'NO MATCH') . "\n";

    // If not match, update with fresh hash
    if (!password_verify('SmartCMS@2026', $hash)) {
        $newHash = password_hash('SmartCMS@2026', PASSWORD_BCRYPT);
        echo "Generating new hash: $newHash\n";
        $updateStmt = $pdo->prepare('UPDATE users SET password=? WHERE email=?');
        $updateStmt->execute([$newHash, 'superadmin@smartcms.local']);
        $updateStmt->execute([$newHash, 'root@smartcms.local']);
        $updateStmt->execute([$newHash, 'cmsadmin@smartx.local']);
        echo "All passwords updated with fresh hash!\n";
    }
} catch (PDOException $e) {
    // Try without password
    $pdo = new PDO('mysql:unix_socket=/run/mysqld/mysqld.sock;dbname=db_ucx', 'root', '');
    $stmt = $pdo->query('SELECT password FROM users WHERE email="superadmin@smartcms.local"');
    $hash = $stmt->fetchColumn();
    echo "Stored hash: $hash\n";
    echo "Verify SmartCMS@2026: " . (password_verify('SmartCMS@2026', $hash) ? 'MATCH!' : 'NO MATCH') . "\n";

    if (!password_verify('SmartCMS@2026', $hash)) {
        $newHash = password_hash('SmartCMS@2026', PASSWORD_BCRYPT);
        $pdo->exec("UPDATE users SET password='$newHash' WHERE email='superadmin@smartcms.local'");
        $pdo->exec("UPDATE users SET password='$newHash' WHERE email='root@smartcms.local'");
        $pdo->exec("UPDATE users SET password='$newHash' WHERE email='cmsadmin@smartx.local'");
        echo "All passwords updated!\n";
    }
}
