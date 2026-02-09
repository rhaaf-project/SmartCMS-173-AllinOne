<?php
/**
 * Password Verification and Reset Script for SmartCMS
 * Run: php verify_password.php
 */

$host = '127.0.0.1';
$dbname = 'db_ucx';
$username = 'root';
$password = '';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8mb4", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    echo "=== SmartCMS Password Checker ===\n\n";

    // Get all users
    $stmt = $pdo->query("SELECT id, name, email, password FROM users");
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Test passwords
    $testPasswords = ['Maja1234', 'SmartCMS@2026', 'admin123', 'Admin@123'];

    foreach ($users as $user) {
        echo "User: {$user['email']} (ID: {$user['id']})\n";
        echo "  Hash: " . substr($user['password'], 0, 30) . "...\n";

        $matched = false;
        foreach ($testPasswords as $testPass) {
            if (password_verify($testPass, $user['password'])) {
                echo "  ✅ PASSWORD MATCH: $testPass\n";
                $matched = true;
                break;
            }
        }

        if (!$matched) {
            echo "  ❌ No password matched from test list\n";
        }
        echo "\n";
    }

    echo "=== Reset Passwords ===\n";
    echo "To reset all passwords to 'Maja1234', uncomment the code below and run again.\n\n";

    // UNCOMMENT TO RESET PASSWORDS:
    // $newHash = password_hash('Maja1234', PASSWORD_BCRYPT);
    // $updateStmt = $pdo->prepare("UPDATE users SET password = ?");
    // $updateStmt->execute([$newHash]);
    // echo "All passwords reset to 'Maja1234'\n";

} catch (PDOException $e) {
    echo "Database Error: " . $e->getMessage() . "\n";
}
