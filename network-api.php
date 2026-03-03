<?php
/**
 * SmartCMS Network Management API
 * Standalone backend for OS-level network management
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Database connection
try {
    $pdo = new PDO('mysql:host=127.0.0.1;dbname=db_ucx;charset=utf8mb4', 'asterisk', 'Maja1234!');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database connection failed']);
    exit;
}

// Auth validation
function validateToken($pdo) {
    $headers = getallheaders();
    $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/Bearer\s+(.+)/i', $authHeader, $m)) return null;
    $token = trim($m[1]);
    $stmt = $pdo->prepare("SELECT id, name, email, role FROM users WHERE remember_token = ? AND is_active = 1");
    $stmt->execute([$token]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$user || !in_array($user['role'], ['superroot', 'admin'])) return null;
    return $user;
}

// ── System Log helper ──────────────────────────────────────────────────────
function logSystemEvent($pdo, $userId, $userName, $category, $action, $target, $description, $details = null, $status = 'success') {
    try {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $stmt = $pdo->prepare("INSERT INTO system_logs (user_id, user_name, category, action, target, description, details, ip_address, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())");
        $stmt->execute([$userId, $userName, $category, $action, $target, $description, $details ? json_encode($details) : null, $ip, $status]);
    } catch (Exception $e) { /* silent fail */ }
}

// Resolve user from token for logging
$_logUser = validateToken($pdo);
$_logUserId = $_logUser ? (int)$_logUser['id'] : null;
$_logUserName = $_logUser ? $_logUser['name'] : 'System';

function isLocalDevice($ip) {
    $localIPs = [];
    $output = shell_exec("hostname -I 2>/dev/null");
    if ($output) $localIPs = array_map('trim', explode(' ', trim($output)));
    $localIPs[] = '127.0.0.1';
    $localIPs[] = 'localhost';
    return in_array($ip, $localIPs);
}

function execCmd($cmd) {
    return trim(shell_exec($cmd . ' 2>&1') ?? '');
}

function safeDeviceName($device) {
    return preg_replace('/[^a-z0-9_-]/i', '', $device);
}

function parseInterfaces() {
    $raw = execCmd('sudo ip -o addr show 2>/dev/null');
    $interfaces = [];
    foreach (explode("\n", $raw) as $line) {
        $line = trim($line);
        if (empty($line)) continue;
        if (preg_match('/^\d+:\s+(\S+)\s+inet\s+(\S+)/', $line, $m)) {
            $name = $m[1];
            if ($name === 'lo' || strpos($name, 'docker') === 0 || strpos($name, 'veth') === 0 || strpos($name, 'br-') === 0) continue;
            $interfaces[] = ['name' => $name, 'ip' => $m[2], 'state' => 'UP'];
        }
    }
    return $interfaces;
}

function parseRoutes() {
    $raw = execCmd('sudo ip route show 2>/dev/null');
    $routes = [];
    foreach (explode("\n", $raw) as $line) {
        $line = trim($line);
        if (empty($line)) continue;
        $route = ['destination' => '', 'gateway' => '', 'interface' => '', 'metric' => '', 'proto' => ''];
        if (preg_match('/^(default|\S+\/\d+|\S+)\s/', $line, $dm)) {
            $route['destination'] = $dm[1];
        }
        if (preg_match('/via\s+(\S+)/', $line, $gm)) {
            $route['gateway'] = $gm[1];
        }
        if (preg_match('/dev\s+(\S+)/', $line, $im)) {
            $route['interface'] = $im[1];
        }
        if (preg_match('/metric\s+(\d+)/', $line, $mm)) {
            $route['metric'] = $mm[1];
        }
        if (preg_match('/proto\s+(\S+)/', $line, $pm)) {
            $route['proto'] = $pm[1];
        }
        // Skip docker/veth/br routes
        $iface = $route['interface'];
        if (strpos($iface, 'docker') === 0 || strpos($iface, 'veth') === 0 || strpos($iface, 'br-') === 0) continue;
        if (!empty($route['destination'])) {
            $routes[] = $route;
        }
    }
    return $routes;
}

function getConnectionName($interface) {
    $output = trim(shell_exec("sudo nmcli -t -f NAME,DEVICE con show --active 2>/dev/null") ?? '');
    foreach (explode("\n", $output) as $line) {
        $parts = explode(":", trim($line), 2);
        if (count($parts) >= 2 && trim($parts[1]) === $interface) {
            return trim($parts[0]);
        }
    }
    return null;
}

function parseFirewall() {
    $raw = execCmd('sudo ufw status numbered 2>/dev/null');
    $verbose = execCmd('sudo ufw status verbose 2>/dev/null');
    $result = ['active' => false, 'default_incoming' => '', 'default_outgoing' => '', 'rules' => []];
    if (strpos($raw, 'Status: active') !== false || strpos($verbose, 'Status: active') !== false) {
        $result['active'] = true;
    }
    if (preg_match('/Default:\s+(\w+)\s+\(incoming\),\s+(\w+)\s+\(outgoing\)/', $verbose, $pm)) {
        $result['default_incoming'] = $pm[1];
        $result['default_outgoing'] = $pm[2];
    }
    $displayNum = 1;
    foreach (explode("\n", $raw) as $line) {
        // Skip IPv6 rules
        if (strpos($line, '(v6)') !== false) continue;
        if (preg_match('/\[\s*(\d+)\]\s+(.+?)\s+(ALLOW IN|DENY IN|REJECT IN|ALLOW OUT|DENY OUT|REJECT OUT)\s+(.+)/', $line, $rm)) {
            $result['rules'][] = [
                'number' => $displayNum++,
                'ufw_number' => (int)$rm[1],
                'to' => trim($rm[2]),
                'action' => trim($rm[3]),
                'from' => trim($rm[4])
            ];
        }
    }
    return $result;
}

function getNetworkSummary() {
    $interfaces = parseInterfaces();
    $routes = parseRoutes();
    $fw = parseFirewall();
    return [
        'interfaces' => $interfaces,
        'route_count' => count($routes),
        'firewall_active' => $fw['active'],
        'firewall_rule_count' => count($fw['rules'])
    ];
}

function validateIP($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}

function validateCIDR($cidr) {
    if ($cidr === 'default') return true;
    if (preg_match('/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/', $cidr)) return true;
    return false;
}

function sanitizeCmd($str) {
    return escapeshellarg($str);
}

// === AUTH CHECK ===
$user = validateToken($pdo);
if (!$user) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

// === ROUTING ===
$action = $_GET['action'] ?? '';
$method = $_SERVER['REQUEST_METHOD'];

switch ($action) {

    // ============================================
    // 1. GET ?action=devices
    // ============================================
    case 'devices':
        $rows = $pdo->query("SELECT id, name, host AS server_ip, port AS server_port, type AS server_type, is_active FROM call_servers ORDER BY type, id")->fetchAll(PDO::FETCH_ASSOC);
        $devices = [];
        foreach ($rows as $row) {
            $row['device_type'] = 'call_server';
            $row['is_local'] = isLocalDevice($row['server_ip']);
            $row['network_info'] = $row['is_local'] ? getNetworkSummary() : null;
            $devices[] = $row;
        }
        echo json_encode(['success' => true, 'devices' => $devices, 'user' => $user]);
        break;

    // ============================================
    // 2. GET ?action=network_info
    // ============================================
    case 'network_info':
        $deviceType = $_GET['device_type'] ?? '';
        $deviceId = (int)($_GET['device_id'] ?? 0);
        $ip = getDeviceIP($pdo, $deviceType, $deviceId);
        if (!$ip) { echo json_encode(['success' => false, 'error' => 'Device not found']); break; }
        $local = isLocalDevice($ip);
        if ($local) {
            echo json_encode(['success' => true, 'is_local' => true, 'interfaces' => parseInterfaces(), 'routes' => parseRoutes(), 'firewall' => parseFirewall(), 'hostname' => execCmd('hostname'), 'uptime' => execCmd('uptime -p')]);
        } else {
            echo json_encode(['success' => true, 'is_local' => false, 'note' => 'Remote device - stored data only']);
        }
        break;

    // ============================================
    // 3. GET ?action=routes
    // ============================================
    case 'routes':
        $routes = parseRoutes();
        echo json_encode(['success' => true, 'routes' => $routes]);
        break;

    // ============================================
    // 4. POST ?action=add_route
    // ============================================
    case 'add_route':
        if ($method !== 'POST') { echo json_encode(['error' => 'Method not allowed']); break; }
        $input = json_decode(file_get_contents('php://input'), true);
        $destination = trim($input['destination'] ?? '');
        $gateway = trim($input['gateway'] ?? '');
        $ifaceName = trim($input['interface'] ?? $input['interface_name'] ?? '');
        $metric = (int)($input['metric'] ?? 100);
        if (empty($destination)) { echo json_encode(['success' => false, 'error' => 'Destination required']); break; }
        if (empty($gateway)) { echo json_encode(['success' => false, 'error' => 'Gateway required']); break; }
        if (empty($ifaceName)) { echo json_encode(['success' => false, 'error' => 'Interface required']); break; }
        $connName = getConnectionName($ifaceName);
        if (!$connName) { echo json_encode(['success' => false, 'error' => 'No active connection on ' . $ifaceName]); break; }
        $nmRoute = $destination . ' ' . $gateway . ' ' . $metric;
        $modCmd = sprintf("sudo nmcli connection modify %s +ipv4.routes %s 2>&1",
            escapeshellarg($connName), escapeshellarg($nmRoute));
        $modResult = execCmd($modCmd);
        $upResult = execCmd(sprintf("sudo nmcli connection up %s 2>&1", escapeshellarg($connName)));
        usleep(300000);
        $verify = execCmd("sudo ip route show " . escapeshellarg($destination));
        $ok = !empty(trim($verify));
        if ($ok) logSystemEvent($pdo, $_logUserId, $_logUserName, 'network', 'create', 'static_route', "Added route $destination via $gateway dev $ifaceName", ['destination'=>$destination, 'gateway'=>$gateway, 'interface'=>$ifaceName, 'metric'=>$metric]);
        echo json_encode(['success' => $ok, 'message' => $ok ? 'Route added' : 'Route may not have been applied: ' . $modResult, 'routes' => parseRoutes()]);
        break;

    // ============================================
    // 5. DELETE ?action=delete_route&id=X
    // ============================================
    case 'delete_route':
        if ($method !== 'DELETE') { echo json_encode(['error' => 'Method not allowed']); break; }
        $input = json_decode(file_get_contents('php://input'), true);
        $destination = trim($input['destination'] ?? '');
        $gateway = trim($input['gateway'] ?? '');
        $ifaceName = trim($input['interface'] ?? '');
        $metric = (int)($input['metric'] ?? 0);
        if (empty($destination)) { echo json_encode(['success' => false, 'error' => 'Destination required']); break; }
        if (empty($ifaceName)) { echo json_encode(['success' => false, 'error' => 'Interface required']); break; }

        $connName = getConnectionName($ifaceName);
        $deleted = false;
        $hasGw = !empty($gateway) && $gateway !== '-';

        // Helper: check if route still exists in runtime
        $routeExists = function($dest) {
            $check = trim(shell_exec("ip route show " . escapeshellarg($dest) . " 2>/dev/null") ?? '');
            return !empty($check);
        };

        if ($connName && $hasGw) {
            // Method 1: nmcli with dest + gw + metric (exact match)
            if ($metric > 0) {
                $nmRoute = "$destination $gateway $metric";
                execCmd(sprintf("sudo nmcli connection modify %s -ipv4.routes %s 2>&1",
                    escapeshellarg($connName), escapeshellarg($nmRoute)));
                execCmd(sprintf("sudo nmcli connection up %s 2>&1", escapeshellarg($connName)));
                usleep(500000);
                if (!$routeExists($destination)) $deleted = true;
            }

            // Method 2: nmcli with dest + gw only (no metric — handles metric mismatch)
            if (!$deleted) {
                $nmRoute = "$destination $gateway";
                execCmd(sprintf("sudo nmcli connection modify %s -ipv4.routes %s 2>&1",
                    escapeshellarg($connName), escapeshellarg($nmRoute)));
                execCmd(sprintf("sudo nmcli connection up %s 2>&1", escapeshellarg($connName)));
                usleep(500000);
                if (!$routeExists($destination)) $deleted = true;
            }

            // Method 3: try common metrics (100, 101, 102) if still not deleted
            if (!$deleted) {
                $storedRaw = trim(shell_exec(sprintf("nmcli -g ipv4.routes connection show %s 2>/dev/null",
                    escapeshellarg($connName))) ?? '');
                // Parse stored routes to find exact match
                foreach (explode(",", $storedRaw) as $sr) {
                    $sr = trim($sr);
                    if (strpos($sr, $destination) === 0) {
                        execCmd(sprintf("sudo nmcli connection modify %s -ipv4.routes %s 2>&1",
                            escapeshellarg($connName), escapeshellarg($sr)));
                    }
                }
                execCmd(sprintf("sudo nmcli connection up %s 2>&1", escapeshellarg($connName)));
                usleep(500000);
                if (!$routeExists($destination)) $deleted = true;
            }
        }

        // Method 4: ip route del (direct kernel delete — always works for runtime)
        if (!$deleted) {
            if ($hasGw) {
                execCmd(sprintf("sudo ip route del %s via %s dev %s 2>&1",
                    escapeshellarg($destination), escapeshellarg($gateway), escapeshellarg($ifaceName)));
            } else {
                execCmd(sprintf("sudo ip route del %s dev %s 2>&1",
                    escapeshellarg($destination), escapeshellarg($ifaceName)));
            }
            usleep(300000);
            if (!$routeExists($destination)) $deleted = true;

            // Best-effort: also remove from nmcli stored config
            if ($connName) {
                $storedRaw = trim(shell_exec(sprintf("nmcli -g ipv4.routes connection show %s 2>/dev/null",
                    escapeshellarg($connName))) ?? '');
                foreach (explode(",", $storedRaw) as $sr) {
                    $sr = trim($sr);
                    if (strpos($sr, $destination) === 0) {
                        shell_exec(sprintf("sudo nmcli connection modify %s -ipv4.routes %s 2>/dev/null",
                            escapeshellarg($connName), escapeshellarg($sr)));
                    }
                }
            }
        }

        $finalCheck = !$routeExists($destination);
        logSystemEvent($pdo, $_logUserId, $_logUserName, 'network', 'delete', 'static_route',
            ($finalCheck ? "Deleted" : "Failed to delete") . " route $destination via $gateway dev $ifaceName",
            ['destination'=>$destination, 'gateway'=>$gateway, 'interface'=>$ifaceName, 'metric'=>$metric],
            $finalCheck ? 'success' : 'failed');
        echo json_encode(['success' => $finalCheck, 'message' => $finalCheck ? 'Route deleted' : 'Route could not be fully removed', 'routes' => parseRoutes()]);
        break;

    // ============================================
    // 6. GET ?action=firewall
    // ============================================
    case 'firewall':
        $deviceType = $_GET['device_type'] ?? '';
        $deviceId = (int)($_GET['device_id'] ?? 0);
        $ip = getDeviceIP($pdo, $deviceType, $deviceId);
        $local = $ip ? isLocalDevice($ip) : false;
        $ufwStatus = null;
        $ufwRules = [];
        if ($local) {
            $fw = parseFirewall();
            $ufwStatus = ['active' => $fw['active'], 'default_incoming' => $fw['default_incoming'], 'default_outgoing' => $fw['default_outgoing']];
            $ufwRules = $fw['rules'];
        }
        $stmt = $pdo->prepare("SELECT * FROM firewall_rules WHERE device_type = ? AND device_id = ? ORDER BY priority");
        $stmt->execute([$deviceType, $deviceId]);
        $dbRules = $stmt->fetchAll(PDO::FETCH_ASSOC);
        echo json_encode(['success' => true, 'is_local' => $local, 'ufw_status' => $ufwStatus, 'ufw_rules' => $ufwRules, 'db_rules' => $dbRules]);
        break;

    // ============================================
    // 7. POST ?action=add_firewall
    // ============================================
    case 'add_firewall':
        if ($method !== 'POST') { echo json_encode(['error' => 'Method not allowed']); break; }
        $input = json_decode(file_get_contents('php://input'), true);
        $deviceType = $input['device_type'] ?? '';
        $deviceId = (int)($input['device_id'] ?? 0);
        $name = trim($input['name'] ?? '');
        $protocol = strtoupper(trim($input['protocol'] ?? 'TCP'));
        $port = trim($input['port'] ?? '');
        $source = trim($input['source'] ?? '');
        $fwAction = strtoupper(trim($input['action'] ?? 'ACCEPT'));
        $priority = (int)($input['priority'] ?? 100);
        $isActive = (int)($input['is_active'] ?? 1);
        if (empty($name)) { echo json_encode(['success' => false, 'error' => 'Rule name required']); break; }
        if (!in_array($protocol, ['TCP', 'UDP', 'ICMP', 'ALL'])) { echo json_encode(['success' => false, 'error' => 'Invalid protocol']); break; }
        if (empty($port)) { echo json_encode(['success' => false, 'error' => 'Port required']); break; }
        if (!in_array($fwAction, ['ACCEPT', 'DROP', 'REJECT'])) { echo json_encode(['success' => false, 'error' => 'Invalid action']); break; }
        $stmt = $pdo->prepare("INSERT INTO firewall_rules (name, protocol, port, source, action, priority, device_type, device_id, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->execute([$name, $protocol, $port, $source ?: 'Any', $fwAction, $priority, $deviceType, $deviceId, $isActive]);
        $ruleId = $pdo->lastInsertId();
        $osResult = null;
        $ip = getDeviceIP($pdo, $deviceType, $deviceId);
        if ($ip && isLocalDevice($ip) && $isActive) {
            $osResult = executeUfwAdd($port, $protocol, $source, $fwAction);
        }
        logSystemEvent($pdo, $_logUserId, $_logUserName, 'network', 'create', 'firewall_rule', "Added firewall: $fwAction $protocol port $port from $source", ['name'=>$name, 'protocol'=>$protocol, 'port'=>$port, 'source'=>$source, 'action'=>$fwAction]);
        echo json_encode(['success' => true, 'id' => $ruleId, 'os_result' => $osResult, 'message' => 'Firewall rule added']);
        break;

    // ============================================
    // 8. DELETE ?action=delete_firewall&id=X
    // ============================================
    case 'delete_firewall':
        if ($method !== 'DELETE') { echo json_encode(['error' => 'Method not allowed']); break; }
        $ruleId = (int)($_GET['id'] ?? 0);
        $stmt = $pdo->prepare("SELECT * FROM firewall_rules WHERE id = ?");
        $stmt->execute([$ruleId]);
        $rule = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$rule) { echo json_encode(['success' => false, 'error' => 'Rule not found']); break; }
        $pdo->prepare("DELETE FROM firewall_rules WHERE id = ?")->execute([$ruleId]);
        $osResult = null;
        $ip = getDeviceIP($pdo, $rule['device_type'], $rule['device_id']);
        if ($ip && isLocalDevice($ip)) {
            $osResult = executeUfwDelete($rule['port'], $rule['protocol'], $rule['source'], $rule['action']);
        }
        logSystemEvent($pdo, $_logUserId, $_logUserName, 'network', 'delete', 'firewall_rule', "Deleted firewall rule #{$ruleId}: {$rule['name']}", ['id'=>$ruleId, 'name'=>$rule['name'], 'port'=>$rule['port']]);
        echo json_encode(['success' => true, 'os_result' => $osResult, 'message' => 'Firewall rule deleted']);
        break;

    // ============================================
    // 9. PUT ?action=edit_route
    // ============================================
    case 'edit_route':
        if ($method !== 'PUT') { echo json_encode(['error' => 'Method not allowed']); break; }
        $input = json_decode(file_get_contents('php://input'), true);
        $oldDest = trim($input['old_destination'] ?? '');
        $oldGw = trim($input['old_gateway'] ?? '');
        $oldIface = trim($input['old_interface'] ?? '');
        $oldMetric = (int)($input['old_metric'] ?? 0);
        $destination = trim($input['destination'] ?? '');
        $gateway = trim($input['gateway'] ?? '');
        $ifaceName = trim($input['interface'] ?? $input['interface_name'] ?? '');
        $metric = (int)($input['metric'] ?? 100);
        if (empty($destination)) { echo json_encode(['success' => false, 'error' => 'Destination required']); break; }
        if (empty($gateway)) { echo json_encode(['success' => false, 'error' => 'Gateway required']); break; }
        if (empty($ifaceName)) { echo json_encode(['success' => false, 'error' => 'Interface required']); break; }
        // Delete old route
        if (!empty($oldDest) && !empty($oldIface)) {
            $oldConn = getConnectionName($oldIface);
            if ($oldConn && !empty($oldGw) && $oldGw !== '-') {
                $oldNm = $oldDest . ' ' . $oldGw . ($oldMetric ? ' ' . $oldMetric : '');
                execCmd(sprintf("sudo nmcli connection modify %s -ipv4.routes %s 2>&1",
                    escapeshellarg($oldConn), escapeshellarg($oldNm)));
            }
        }
        // Add new route
        $connName = getConnectionName($ifaceName);
        if (!$connName) { echo json_encode(['success' => false, 'error' => 'No active connection on ' . $ifaceName]); break; }
        $nmRoute = $destination . ' ' . $gateway . ' ' . $metric;
        execCmd(sprintf("sudo nmcli connection modify %s +ipv4.routes %s 2>&1",
            escapeshellarg($connName), escapeshellarg($nmRoute)));
        // Apply (bring up the connections that changed)
        execCmd(sprintf("sudo nmcli connection up %s 2>&1", escapeshellarg($connName)));
        if (!empty($oldIface) && $oldIface !== $ifaceName) {
            $oldConn2 = getConnectionName($oldIface);
            if ($oldConn2) execCmd(sprintf("sudo nmcli connection up %s 2>&1", escapeshellarg($oldConn2)));
        }
        usleep(300000);
        logSystemEvent($pdo, $_logUserId, $_logUserName, 'network', 'update', 'static_route', "Updated route $oldDest -> $destination via $gateway", ['old'=>['dest'=>$oldDest,'gw'=>$oldGw,'iface'=>$oldIface], 'new'=>['dest'=>$destination,'gw'=>$gateway,'iface'=>$ifaceName,'metric'=>$metric]]);
        echo json_encode(['success' => true, 'message' => 'Route updated', 'routes' => parseRoutes()]);
        break;

    // ============================================
    // 10. PUT ?action=edit_firewall
    // ============================================
    case 'edit_firewall':
        if ($method !== 'PUT') { echo json_encode(['error' => 'Method not allowed']); break; }
        $input = json_decode(file_get_contents('php://input'), true);
        $id = (int)($input['id'] ?? 0);
        $name = trim($input['name'] ?? '');
        $protocol = strtoupper(trim($input['protocol'] ?? 'TCP'));
        $port = trim($input['port'] ?? '');
        $source = trim($input['source'] ?? '');
        $fwAction = strtoupper(trim($input['action'] ?? 'ACCEPT'));
        $priority = (int)($input['priority'] ?? 100);
        $isActive = (int)($input['is_active'] ?? 1);
        $stmt = $pdo->prepare("SELECT * FROM firewall_rules WHERE id = ?");
        $stmt->execute([$id]);
        $oldRule = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$oldRule) { echo json_encode(['success' => false, 'error' => 'Rule not found']); break; }
        if (empty($name)) { echo json_encode(['success' => false, 'error' => 'Name required']); break; }
        if (!in_array($protocol, ['TCP', 'UDP', 'ICMP', 'ALL'])) { echo json_encode(['success' => false, 'error' => 'Invalid protocol']); break; }
        if (empty($port)) { echo json_encode(['success' => false, 'error' => 'Port required']); break; }
        if (!in_array($fwAction, ['ACCEPT', 'DROP', 'REJECT'])) { echo json_encode(['success' => false, 'error' => 'Invalid action']); break; }
        $stmt = $pdo->prepare("UPDATE firewall_rules SET name=?, protocol=?, port=?, source=?, action=?, priority=?, is_active=? WHERE id=?");
        $stmt->execute([$name, $protocol, $port, $source ?: 'Any', $fwAction, $priority, $isActive, $id]);
        $osResult = null;
        $ip = getDeviceIP($pdo, $oldRule['device_type'], $oldRule['device_id']);
        if ($ip && isLocalDevice($ip)) {
            $osResult = executeUfwDelete($oldRule['port'], $oldRule['protocol'], $oldRule['source'], $oldRule['action']);
            if ($isActive) {
                $addResult = executeUfwAdd($port, $protocol, $source, $fwAction);
                $osResult = ($osResult ? $osResult . "\n" : '') . $addResult;
            }
        }
        logSystemEvent($pdo, $_logUserId, $_logUserName, 'network', 'update', 'firewall_rule', "Updated firewall rule #{$id}: {$name}", ['id'=>$id, 'name'=>$name, 'protocol'=>$protocol, 'port'=>$port, 'source'=>$source, 'action'=>$fwAction]);
        echo json_encode(['success' => true, 'os_result' => $osResult, 'message' => 'Firewall rule updated']);
        break;

    // ============================================
    // 11. DELETE ?action=delete_os_firewall
    // ============================================
    case 'delete_os_firewall':
        if ($method !== 'DELETE') { echo json_encode(['error' => 'Method not allowed']); break; }
        $ruleNum = (int)($_GET['rule_number'] ?? 0);
        if ($ruleNum < 1) { echo json_encode(['success' => false, 'error' => 'Invalid rule number']); break; }
        // Delete both IPv4 rule and its IPv6 counterpart
        // First, get the rule text to find what to delete
        $beforeRaw = execCmd('sudo ufw status numbered 2>/dev/null');
        $ruleText = '';
        foreach (explode("\n", $beforeRaw) as $line) {
            if (preg_match('/\[\s*' . $ruleNum . '\]/', $line) && strpos($line, '(v6)') === false) {
                $ruleText = $line;
                break;
            }
        }
        // Delete the rule by number
        $osResult = execCmd("sudo ufw --force delete " . $ruleNum);
        // Also delete the matching v6 rule if it exists
        // After deleting, numbers shift, so re-read and find matching v6 rule
        if (!empty($ruleText)) {
            // Extract the port/proto from deleted rule to match v6
            if (preg_match('/\]\s+(\S+)\s+/', $ruleText, $ptm)) {
                $portProto = $ptm[1];
                $afterRaw = execCmd('sudo ufw status numbered 2>/dev/null');
                foreach (explode("\n", $afterRaw) as $line) {
                    if (strpos($line, '(v6)') !== false && strpos($line, $portProto) !== false) {
                        if (preg_match('/\[\s*(\d+)\]/', $line, $v6m)) {
                            execCmd("sudo ufw --force delete " . (int)$v6m[1]);
                        }
                        break;
                    }
                }
            }
        }
        $updatedFw = parseFirewall();
        echo json_encode(['success' => true, 'os_result' => $osResult, 'rules' => $updatedFw['rules'], 'message' => 'Firewall rule deleted']);
        break;

    // ============================================
    // 12. PUT ?action=edit_os_firewall
    // ============================================
    case 'edit_os_firewall':
        if ($method !== 'PUT') { echo json_encode(['error' => 'Method not allowed']); break; }
        $input = json_decode(file_get_contents('php://input'), true);
        $ruleNum = (int)($input['rule_number'] ?? 0);
        $port = trim($input['port'] ?? '');
        $protocol = strtoupper(trim($input['protocol'] ?? 'TCP'));
        $source = trim($input['source'] ?? '');
        $fwAction = strtoupper(trim($input['action'] ?? 'ACCEPT'));
        if ($ruleNum < 1) { echo json_encode(['success' => false, 'error' => 'Invalid rule number']); break; }
        if (empty($port)) { echo json_encode(['success' => false, 'error' => 'Port required']); break; }
        $delResult = execCmd("sudo ufw --force delete " . $ruleNum);
        $addResult = executeUfwAdd($port, $protocol, $source, $fwAction);
        $updatedFw = parseFirewall();
        echo json_encode(['success' => true, 'os_result' => $delResult . "\n" . $addResult, 'rules' => $updatedFw['rules'], 'message' => 'Firewall rule updated']);
        break;

    // ============================================
    // 13. GET ?action=interfaces
    // ============================================
    case 'interfaces':
        $raw = execCmd('sudo ip -o link show 2>/dev/null');
        $ifaces = [];
        foreach (explode("\n", $raw) as $line) {
            if (preg_match('/^\d+:\s+(\S+):/', $line, $m)) {
                $name = $m[1];
                if (in_array($name, ['lo']) || strpos($name, 'docker') === 0 || strpos($name, 'veth') === 0 || strpos($name, 'br-') === 0) continue;
                $ifaces[] = $name;
            }
        }
        echo json_encode(['success' => true, 'interfaces' => $ifaces]);
        break;

    // ============================================
    // 14. DELETE ?action=delete_os_route
    // ============================================
    case 'delete_os_route':
        if ($method !== 'DELETE') { echo json_encode(['error' => 'Method not allowed']); break; }
        $input = json_decode(file_get_contents('php://input'), true);
        $destination = trim($input['destination'] ?? '');
        $gateway = trim($input['gateway'] ?? '');
        $ifaceName = trim($input['interface'] ?? '');
        $metric = (int)($input['metric'] ?? 0);
        if (empty($destination)) { echo json_encode(['success' => false, 'error' => 'Destination required']); break; }
        if (empty($ifaceName)) { echo json_encode(['success' => false, 'error' => 'Interface required']); break; }
        $connName = getConnectionName($ifaceName);
        if ($connName && !empty($gateway) && $gateway !== '-') {
            $nmRoute = $destination . ' ' . $gateway . ($metric ? ' ' . $metric : '');
            execCmd(sprintf("sudo nmcli connection modify %s -ipv4.routes %s 2>&1",
                escapeshellarg($connName), escapeshellarg($nmRoute)));
            execCmd(sprintf("sudo nmcli connection up %s 2>&1", escapeshellarg($connName)));
        } else {
            execCmd("sudo ip route del " . escapeshellarg($destination) . " 2>&1");
        }
        usleep(300000);
        echo json_encode(['success' => true, 'message' => 'Route deleted', 'routes' => parseRoutes()]);
        break;

    // ============================================
    // 15. PUT ?action=edit_os_route
    // ============================================
    case 'edit_os_route':
        if ($method !== 'PUT') { echo json_encode(['error' => 'Method not allowed']); break; }
        $input = json_decode(file_get_contents('php://input'), true);
        $oldDest = trim($input['old_destination'] ?? '');
        $oldGw = trim($input['old_gateway'] ?? '');
        $oldIface = trim($input['old_interface'] ?? '');
        $oldMetric = (int)($input['old_metric'] ?? 0);
        $destination = trim($input['destination'] ?? '');
        $gateway = trim($input['gateway'] ?? '');
        $ifaceName = trim($input['interface'] ?? '');
        $metric = (int)($input['metric'] ?? 100);
        if (empty($destination)) { echo json_encode(['success' => false, 'error' => 'Destination required']); break; }
        if (empty($gateway)) { echo json_encode(['success' => false, 'error' => 'Gateway required']); break; }
        if (empty($ifaceName)) { echo json_encode(['success' => false, 'error' => 'Interface required']); break; }
        // Delete old via nmcli
        if (!empty($oldDest) && !empty($oldIface)) {
            $oldConn = getConnectionName($oldIface);
            if ($oldConn && !empty($oldGw) && $oldGw !== '-') {
                $oldNm = $oldDest . ' ' . $oldGw . ($oldMetric ? ' ' . $oldMetric : '');
                execCmd(sprintf("sudo nmcli connection modify %s -ipv4.routes %s 2>&1",
                    escapeshellarg($oldConn), escapeshellarg($oldNm)));
            }
        }
        // Add new via nmcli
        $connName = getConnectionName($ifaceName);
        if (!$connName) { echo json_encode(['success' => false, 'error' => 'No active connection on ' . $ifaceName]); break; }
        $nmRoute = $destination . ' ' . $gateway . ' ' . $metric;
        execCmd(sprintf("sudo nmcli connection modify %s +ipv4.routes %s 2>&1",
            escapeshellarg($connName), escapeshellarg($nmRoute)));
        execCmd(sprintf("sudo nmcli connection up %s 2>&1", escapeshellarg($connName)));
        if (!empty($oldIface) && $oldIface !== $ifaceName) {
            $oldConn2 = getConnectionName($oldIface);
            if ($oldConn2) execCmd(sprintf("sudo nmcli connection up %s 2>&1", escapeshellarg($oldConn2)));
        }
        usleep(300000);
        echo json_encode(['success' => true, 'message' => 'Route updated', 'routes' => parseRoutes()]);
        break;

    // ============================================
    // 16. GET ?action=ip_config
    // ============================================
    case 'ip_config':
        $interfaces = [];
        // Get ethernet devices
        $devRaw = execCmd('nmcli -t -f DEVICE,TYPE device status 2>/dev/null');
        $ethDevices = [];
        foreach (explode("\n", $devRaw) as $line) {
            $parts = explode(':', trim($line), 2);
            if (count($parts) < 2) continue;
            $dev = $parts[0];
            if ($parts[1] !== 'ethernet') continue;
            if ($dev === 'lo' || strpos($dev, 'docker') === 0 || strpos($dev, 'veth') === 0 || strpos($dev, 'br-') === 0) continue;
            $ethDevices[] = $dev;
        }

        foreach ($ethDevices as $device) {
            // Get connection name
            $connRaw = execCmd('nmcli -t -f GENERAL.CONNECTION device show ' . escapeshellarg($device) . ' 2>/dev/null');
            $connName = '';
            foreach (explode("\n", $connRaw) as $cl) {
                if (preg_match('/^GENERAL\.CONNECTION:(.+)/', $cl, $m)) {
                    $connName = trim($m[1]);
                }
            }
            if (empty($connName) || $connName === '--') continue;

            $config = [
                'connection_name' => $connName,
                'device' => $device,
                'method' => '',
                'addresses' => [],
                'gateway' => '',
                'dns' => [],
                'mac' => '',
                'state' => ''
            ];

            // Get connection details
            $detail = execCmd('nmcli -t -f ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.dns connection show ' . escapeshellarg($connName) . ' 2>/dev/null');
            foreach (explode("\n", $detail) as $dline) {
                $dline = trim($dline);
                if (preg_match('/^ipv4\.method:(.*)/', $dline, $m)) {
                    $config['method'] = trim($m[1]);
                } elseif (preg_match('/^ipv4\.addresses:(.+)/', $dline, $m)) {
                    $addr = trim($m[1]);
                    if (!empty($addr) && $addr !== '--') $config['addresses'][] = $addr;
                } elseif (preg_match('/^ipv4\.gateway:(.+)/', $dline, $m)) {
                    $gw = trim($m[1]);
                    if ($gw !== '--' && $gw !== '') $config['gateway'] = $gw;
                } elseif (preg_match('/^ipv4\.dns:(.+)/', $dline, $m)) {
                    $dns = trim($m[1]);
                    if (!empty($dns) && $dns !== '--') $config['dns'][] = $dns;
                }
            }

            $config['mac'] = trim(execCmd('cat /sys/class/net/' . escapeshellarg($device) . '/address 2>/dev/null'));
            $config['state'] = trim(execCmd('cat /sys/class/net/' . escapeshellarg($device) . '/operstate 2>/dev/null'));

            // Check for pending IP change
            $pendingFile = '/tmp/smartcms_ip_pending_' . safeDeviceName($device);
            if (file_exists($pendingFile)) {
                $pending = json_decode(file_get_contents($pendingFile), true);
                $config['pending_confirm'] = true;
                $elapsed = time() - ($pending['timestamp'] ?? time());
                $config['pending_remaining'] = max(0, ($pending['timeout'] ?? 120) - $elapsed);
                $config['pending_old_config'] = $pending['old_config'] ?? null;
            }

            $interfaces[] = $config;
        }

        echo json_encode(['success' => true, 'interfaces' => $interfaces]);
        break;

    // ============================================
    // 17. PUT ?action=set_ip
    // ============================================
    case 'set_ip':
        if ($method !== 'PUT') { echo json_encode(['error' => 'Method not allowed']); break; }
        $input = json_decode(file_get_contents('php://input'), true);
        $connName = trim($input['connection_name'] ?? '');
        $device = trim($input['device'] ?? '');
        $ipMethod = trim($input['method'] ?? 'manual');
        $address = trim($input['address'] ?? '');
        $gateway = trim($input['gateway'] ?? '');
        // Accept DNS as comma/space-separated string or array
        $dnsRaw = $input['dns'] ?? '8.8.8.8';
        if (is_array($dnsRaw)) {
            $dns = implode(' ', array_filter(array_map('trim', $dnsRaw)));
        } else {
            $dns = implode(' ', array_filter(array_map('trim', preg_split('/[,\s]+/', $dnsRaw))));
        }
        if (empty($dns)) $dns = '8.8.8.8';

        if (empty($connName) || empty($device)) {
            echo json_encode(['success' => false, 'error' => 'Connection name and device required']);
            break;
        }
        if ($ipMethod === 'manual' && empty($address)) {
            echo json_encode(['success' => false, 'error' => 'IP address required for static config']);
            break;
        }

        $safeDevice = safeDeviceName($device);
        $revertFile = '/tmp/smartcms_ip_revert_' . $safeDevice . '.sh';
        $pendingFile = '/tmp/smartcms_ip_pending_' . $safeDevice;

        // Get current config for revert
        $currentDetail = execCmd('nmcli -t -f ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.dns connection show ' . escapeshellarg($connName) . ' 2>/dev/null');
        $cur = ['method' => '', 'address' => '', 'gateway' => '', 'dns' => []];
        foreach (explode("\n", $currentDetail) as $dline) {
            if (preg_match('/^ipv4\.method:(.*)/', $dline, $m)) $cur['method'] = trim($m[1]);
            elseif (preg_match('/^ipv4\.addresses:(.+)/', $dline, $m) && trim($m[1]) !== '--') $cur['address'] = trim($m[1]);
            elseif (preg_match('/^ipv4\.gateway:(.+)/', $dline, $m) && trim($m[1]) !== '--') $cur['gateway'] = trim($m[1]);
            elseif (preg_match('/^ipv4\.dns:(.+)/', $dline, $m) && trim($m[1]) !== '--') $cur['dns'][] = trim($m[1]);
        }

        // Write revert script
        $revert = "#!/bin/bash\n# Auto-revert IP for {$device}\n";
        $revert .= "sudo /usr/bin/nmcli connection modify " . escapeshellarg($connName);
        $revert .= " ipv4.method " . escapeshellarg($cur['method'] ?: 'manual');
        if (!empty($cur['address'])) $revert .= " ipv4.addresses " . escapeshellarg($cur['address']);
        else $revert .= ' ipv4.addresses ""';
        if (!empty($cur['gateway'])) $revert .= " ipv4.gateway " . escapeshellarg($cur['gateway']);
        else $revert .= ' ipv4.gateway ""';
        if (!empty($cur['dns'])) $revert .= " ipv4.dns " . escapeshellarg(implode(' ', $cur['dns']));
        $revert .= "\nsudo /usr/bin/nmcli connection up " . escapeshellarg($connName) . "\n";
        $revert .= "rm -f " . escapeshellarg($pendingFile) . "\n";
        $revert .= "rm -f " . escapeshellarg($revertFile) . "\n";

        file_put_contents($revertFile, $revert);
        chmod($revertFile, 0755);

        // Apply new config
        $modCmd = 'sudo nmcli connection modify ' . escapeshellarg($connName);
        if ($ipMethod === 'auto') {
            $modCmd .= ' ipv4.method auto ipv4.addresses "" ipv4.gateway ""';
        } else {
            $modCmd .= ' ipv4.method manual ipv4.addresses ' . escapeshellarg($address);
            if (!empty($gateway)) $modCmd .= ' ipv4.gateway ' . escapeshellarg($gateway);
            else $modCmd .= ' ipv4.gateway ""';
        }
        if (!empty($dns)) $modCmd .= ' ipv4.dns ' . escapeshellarg($dns);

        $modResult = execCmd($modCmd);

        // Schedule revert in 120 seconds
        $pidOutput = [];
        exec('nohup bash -c ' . escapeshellarg('sleep 120 && bash ' . $revertFile) . ' > /dev/null 2>&1 & echo $!', $pidOutput);
        $pid = trim($pidOutput[0] ?? '');

        // Save pending info
        file_put_contents($pendingFile, json_encode([
            'pid' => $pid,
            'revert_file' => $revertFile,
            'timestamp' => time(),
            'timeout' => 120,
            'old_config' => $cur
        ]));

        // Apply connection
        $upResult = execCmd('sudo nmcli connection up ' . escapeshellarg($connName));

        echo json_encode([
            'success' => true,
            'modify_result' => $modResult,
            'up_result' => $upResult,
            'pending_confirm' => true,
            'timeout_seconds' => 120,
            'message' => 'IP changed. Confirm within 2 minutes or it will auto-revert.'
        ]);
        break;

    // ============================================
    // 18. POST ?action=confirm_ip
    // ============================================
    case 'confirm_ip':
        if ($method !== 'POST') { echo json_encode(['error' => 'Method not allowed']); break; }
        $input = json_decode(file_get_contents('php://input'), true);
        $device = trim($input['device'] ?? '');
        if (empty($device)) { echo json_encode(['success' => false, 'error' => 'Device name required']); break; }

        $pendingFile = '/tmp/smartcms_ip_pending_' . safeDeviceName($device);
        if (!file_exists($pendingFile)) {
            echo json_encode(['success' => false, 'error' => 'No pending IP change for this device']);
            break;
        }

        $pending = json_decode(file_get_contents($pendingFile), true);
        $pid = $pending['pid'] ?? '';

        // Kill revert timer
        if (!empty($pid) && is_numeric($pid)) {
            exec('kill ' . intval($pid) . ' 2>/dev/null');
            $children = trim(shell_exec('pgrep -P ' . intval($pid) . ' 2>/dev/null') ?? '');
            if (!empty($children)) {
                foreach (explode("\n", $children) as $child) {
                    $child = trim($child);
                    if (is_numeric($child)) exec('kill ' . intval($child) . ' 2>/dev/null');
                }
            }
        }

        // Clean up
        $revertFile = $pending['revert_file'] ?? '';
        if (!empty($revertFile) && file_exists($revertFile)) unlink($revertFile);
        if (file_exists($pendingFile)) unlink($pendingFile);

        logSystemEvent($pdo, $_logUserId, $_logUserName, 'network', 'execute', 'ip_config', "Confirmed IP change on $ifaceName", ['interface'=>$ifaceName]);
        echo json_encode(['success' => true, 'message' => 'IP change confirmed']);
        break;

    // ============================================
    // 19. POST ?action=revert_ip
    // ============================================
    case 'revert_ip':
        if ($method !== 'POST') { echo json_encode(['error' => 'Method not allowed']); break; }
        $input = json_decode(file_get_contents('php://input'), true);
        $device = trim($input['device'] ?? '');
        if (empty($device)) { echo json_encode(['success' => false, 'error' => 'Device name required']); break; }

        $pendingFile = '/tmp/smartcms_ip_pending_' . safeDeviceName($device);
        if (!file_exists($pendingFile)) {
            echo json_encode(['success' => false, 'error' => 'No pending IP change']);
            break;
        }

        $pending = json_decode(file_get_contents($pendingFile), true);
        $pid = $pending['pid'] ?? '';
        $revertFile = $pending['revert_file'] ?? '';

        // Kill timer
        if (!empty($pid) && is_numeric($pid)) {
            exec('kill ' . intval($pid) . ' 2>/dev/null');
            $children = trim(shell_exec('pgrep -P ' . intval($pid) . ' 2>/dev/null') ?? '');
            if (!empty($children)) {
                foreach (explode("\n", $children) as $child) {
                    $child = trim($child);
                    if (is_numeric($child)) exec('kill ' . intval($child) . ' 2>/dev/null');
                }
            }
        }

        // Run revert immediately
        $result = '';
        if (!empty($revertFile) && file_exists($revertFile)) {
            $result = execCmd('bash ' . escapeshellarg($revertFile));
        }

        // Clean up (revert script also cleans, but just in case)
        if (file_exists($pendingFile)) unlink($pendingFile);
        if (!empty($revertFile) && file_exists($revertFile)) unlink($revertFile);

        echo json_encode(['success' => true, 'result' => $result, 'message' => 'IP reverted to previous configuration']);
        break;

    // ============================================
    // 20. GET ?action=system_status
    // ============================================
    case 'system_status':
        $deviceType = $_GET['device_type'] ?? '';
        $deviceId = (int)($_GET['device_id'] ?? 0);
        $ip = getDeviceIP($pdo, $deviceType, $deviceId);
        $local = $ip ? isLocalDevice($ip) : false;
        if (!$local) {
            echo json_encode(['success' => true, 'is_local' => false, 'status' => 'unknown', 'uptime' => 'Remote device']);
            break;
        }
        $status = trim(shell_exec("sudo docker inspect asterisk --format '{{.State.Status}}' 2>/dev/null") ?? '');
        $uptime = trim(shell_exec("sudo docker ps --format '{{.Status}}' --filter 'name=^asterisk$' 2>/dev/null") ?? '');
        echo json_encode([
            'success' => true,
            'is_local' => true,
            'status' => $status ?: 'unknown',
            'uptime' => $uptime ?: ($status === 'running' ? 'Running' : 'Not running')
        ]);
        break;

    // ============================================
    // 21. POST ?action=system_control
    // ============================================
    case 'system_control':
        if ($method !== 'POST') { echo json_encode(['error' => 'Method not allowed']); break; }
        $input = json_decode(file_get_contents('php://input'), true);
        $command = $input['command'] ?? '';
        $deviceType = $input['device_type'] ?? '';
        $deviceId = (int)($input['device_id'] ?? 0);

        // Validate command
        if (!in_array($command, ['restart', 'shutdown', 'start', 'os_restart', 'os_shutdown'], true)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Invalid command']);
            break;
        }

        // Only allow on local device
        $ip = getDeviceIP($pdo, $deviceType, $deviceId);
        $local = $ip ? isLocalDevice($ip) : false;
        if (!$local) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Remote system control is not available']);
            break;
        }

        // OS-level restart/shutdown
        if ($command === 'os_restart' || $command === 'os_shutdown') {
            $osCmd = $command === 'os_restart'
                ? 'sudo shutdown -r +1 "SmartCMS: System restart" 2>&1'
                : 'sudo shutdown -h +1 "SmartCMS: System shutdown" 2>&1';
            $osLabel = $command === 'os_restart' ? 'Device restart scheduled' : 'Device shutdown scheduled';
            $output = trim(shell_exec($osCmd) ?? '');
            logSystemEvent($pdo, $_logUserId, $_logUserName, 'system', $command, 'device',
                $osLabel . ' (1 minute)',
                ['command' => $command, 'output' => $output],
                'success');
            echo json_encode([
                'success' => true,
                'status' => 'scheduled',
                'message' => $osLabel . '. The device will ' . ($command === 'os_restart' ? 'restart' : 'shut down') . ' in 1 minute.'
            ]);
            break;
        }

        // Execute docker command
        $dockerCmd = '';
        $actionLabel = '';
        switch ($command) {
            case 'restart':
                $dockerCmd = 'sudo docker restart asterisk 2>&1';
                $actionLabel = 'restarted';
                break;
            case 'shutdown':
                $dockerCmd = 'sudo docker stop asterisk 2>&1';
                $actionLabel = 'stopped';
                break;
            case 'start':
                $dockerCmd = 'sudo docker start asterisk 2>&1';
                $actionLabel = 'started';
                break;
        }

        $output = trim(shell_exec($dockerCmd) ?? '');
        sleep(2);

        // Get new status
        $newStatus = trim(shell_exec("sudo docker inspect asterisk --format '{{.State.Status}}' 2>/dev/null") ?? '');

        // Determine success
        $success = false;
        if ($command === 'shutdown' && in_array($newStatus, ['exited', 'stopped'])) $success = true;
        if ($command === 'start' && $newStatus === 'running') $success = true;
        if ($command === 'restart' && $newStatus === 'running') $success = true;

        // Log
        logSystemEvent($pdo, $_logUserId, $_logUserName, 'system', $command, 'asterisk',
            "System {$actionLabel}" . ($success ? '' : ' (may have failed)'),
            ['command' => $command, 'output' => $output, 'new_status' => $newStatus],
            $success ? 'success' : 'warning');

        echo json_encode([
            'success' => $success,
            'status' => $newStatus ?: 'unknown',
            'message' => $success ? "System {$actionLabel} successfully" : "Command executed but status is {$newStatus}"
        ]);
        break;

    default:
        echo json_encode(['error' => 'Unknown action', 'valid_actions' => [
            'devices', 'network_info', 'routes', 'add_route', 'edit_route', 'delete_route',
            'firewall', 'add_firewall', 'edit_firewall', 'delete_firewall',
            'delete_os_firewall', 'edit_os_firewall', 'delete_os_route', 'edit_os_route',
            'interfaces', 'ip_config', 'set_ip', 'confirm_ip', 'revert_ip',
            'system_status', 'system_control'
        ]]);
        break;
}

// === HELPER FUNCTIONS ===

function getDeviceIP($pdo, $deviceType, $deviceId) {
    if ($deviceType === 'call_server') {
        $stmt = $pdo->prepare("SELECT host FROM call_servers WHERE id = ?");
        $stmt->execute([$deviceId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ? $row['host'] : null;
    } elseif ($deviceType === 'sbc') {
        $stmt = $pdo->prepare("SELECT sip_server FROM sbcs WHERE id = ?");
        $stmt->execute([$deviceId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ? $row['sip_server'] : null;
    }
    return null;
}

function executeUfwAdd($port, $protocol, $source, $action) {
    $protoLower = strtolower($protocol);
    $ufwAction = '';
    switch (strtoupper($action)) {
        case 'ACCEPT': $ufwAction = 'allow'; break;
        case 'DROP': $ufwAction = 'deny'; break;
        case 'REJECT': $ufwAction = 'reject'; break;
        default: return 'Invalid action';
    }
    $safePort = escapeshellarg($port);
    $safeSrc = (!empty($source) && $source !== 'Any') ? escapeshellarg($source) : 'any';
    // Always use "from ... to ..." form to only create IPv4 rule (not both v4+v6)
    if ($protocol === 'ALL') {
        $cmd = "sudo ufw {$ufwAction} from {$safeSrc} to any port {$safePort}";
    } else {
        $cmd = "sudo ufw {$ufwAction} from {$safeSrc} to any port {$safePort} proto {$protoLower}";
    }
    return execCmd($cmd);
}

function executeUfwDelete($port, $protocol, $source, $action) {
    $protoLower = strtolower($protocol);
    $ufwAction = '';
    switch (strtoupper($action)) {
        case 'ACCEPT': $ufwAction = 'allow'; break;
        case 'DROP': $ufwAction = 'deny'; break;
        case 'REJECT': $ufwAction = 'reject'; break;
        default: return 'Invalid action';
    }
    $safePort = escapeshellarg($port);
    if (!empty($source) && $source !== 'Any') {
        $safeSrc = escapeshellarg($source);
        if ($protocol === 'ALL') {
            $cmd = "sudo ufw --force delete {$ufwAction} from {$safeSrc} to any port {$safePort}";
        } else {
            $cmd = "sudo ufw --force delete {$ufwAction} from {$safeSrc} to any port {$safePort} proto {$protoLower}";
        }
    } else {
        if ($protocol === 'ALL') {
            $cmd = "sudo ufw --force delete {$ufwAction} {$safePort}";
        } else {
            $cmd = "sudo ufw --force delete {$ufwAction} {$safePort}/{$protoLower}";
        }
    }
    return execCmd($cmd);
}

function persistRoutes($pdo, $deviceType, $deviceId) {
    $stmt = $pdo->prepare("SELECT destination, gateway, interface_name, metric FROM static_routes WHERE device_type = ? AND device_id = ? AND is_active = 1");
    $stmt->execute([$deviceType, $deviceId]);
    $routes = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $lines = [];
    foreach ($routes as $r) {
        if (!empty($r['destination']) && !empty($r['gateway'])) {
            $line = "{$r['destination']} via {$r['gateway']}";
            if (!empty($r['interface_name'])) $line .= " dev {$r['interface_name']}";
            if (!empty($r['metric'])) $line .= " metric {$r['metric']}";
            $lines[] = $line;
        }
    }
    file_put_contents('/etc/network/routes.smartcms', implode("\n", $lines) . "\n");
}
