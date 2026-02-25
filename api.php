<?php
date_default_timezone_set("Asia/Jakarta"); // WIB UTC+7
/**
 * Simple API Backend for SmartCMS Angular
 * Database: db_ucx (MariaDB)
 * 
 * Run with: php -S localhost:8000 api.php
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// If the requested URI exists as a file, let the PHP built-in server handle it directly
// This is essential when running with php -S localhost:8000 api.php
$requestPath = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($requestPath !== '/' && file_exists(__DIR__ . $requestPath) && is_file(__DIR__ . $requestPath)) {
    return false;
}

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Database connection
$host = '127.0.0.1';
$dbname = 'db_ucx';
$username = 'asterisk';
$password = 'Maja1234!';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8mb4", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec("SET time_zone = '+07:00'"); // WIB timezone
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database connection failed: ' . $e->getMessage()]);
    exit;
}

// Parse request
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
// Handle subdirectory deployment (e.g. /SmartCMS/api/v1/...)
if (preg_match('#/api/v1/(.*)#', $uri, $matches)) {
    $uri = $matches[1];
} elseif (preg_match('#/api/(.*)#', $uri, $matches)) {
    $uri = $matches[1];
} else {
    $uri = str_replace(['/api/v1/', '/api/'], '', $uri);
}
$method = $_SERVER['REQUEST_METHOD'];
$input = json_decode(file_get_contents('php://input'), true) ?? [];

// Simple router
$parts = explode('/', trim($uri, '/'));
$resource = $parts[0] ?? '';
$id = $parts[1] ?? null;

// Table mapping
$tableMap = [
    'companies' => 'customers',
    'customers' => 'customers',
    'head-offices' => 'head_offices',
    'branches' => 'branches',
    'sub-branches' => 'sub_branches',
    'call-servers' => 'call_servers',
    'lines' => 'lines',
    'extensions' => 'extensions',
    'vpws' => 'private_wires',
    'cas' => 'cas',
    'device-3rd-parties' => 'device_3rd_parties',
    'provisioning-brands' => 'provisioning_brands',
    'provisioning-models' => 'provisioning_models',
    'provisioning-templates' => 'provisioning_templates',
    'private-wires' => 'private_wires',
    'trunks' => 'trunks',
    'intercoms' => 'intercoms',
    'sbcs' => 'sbcs',
    'inbound-routings' => 'inbound_routings',
    'outbound-routings' => 'outbound_routings',
    'sbc-routes' => 'sbc_routes',
    'ring-groups' => 'ring_groups',
    'ivr' => 'ivr',
    'time-conditions' => 'time_conditions',
    'conferences' => 'conferences',
    'system-logs' => 'system_logs',
    'activity-logs' => 'activity_logs',
    'activity_logs' => 'activity_logs',
    'call-logs' => 'call_logs',
    'alarm-notifications' => 'alarm_notifications',
    'users' => 'users',
    'announcements' => 'announcements',
    'recordings' => 'recordings',
    'ivr-entries' => 'ivr_entries',
    'black-lists' => 'black_lists',
    'custom-destinations' => 'custom_destinations',
    'misc-destinations' => 'misc_destinations',
    'turret-users' => 'turret_users',
    'turret-templates' => 'turret_templates',
    'turret-groups' => 'turret_groups',
    'turret-group-members' => 'turret_group_members',
    'phone-directories' => 'phone_directories',
    'turret-policies' => 'turret_policies',
    'turret-user-phonebooks' => 'turret_user_phonebooks',
    'turret-channel-states' => 'turret_channel_states',
    'turret-user-preferences' => 'turret_user_preferences',
    'static-routes' => 'static_routes',
    'firewall-rules' => 'firewall_rules',
    'role-permissions' => 'role_permissions',
];

$table = $tableMap[$resource] ?? null;

// Login endpoint
if ($resource === 'login' && $method === 'POST') {
    $email = $input['email'] ?? '';
    $password = $input['password'] ?? '';

    if (!$email || !$password) {
        http_response_code(400);
        echo json_encode(['error' => 'Email and password are required']);
        exit;
    }

    try {
        $stmt = $pdo->prepare("SELECT id, name, email, password, role, profile_image, is_active FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user || !password_verify($password, $user['password'])) {
            http_response_code(401);
            echo json_encode(['error' => 'Invalid email or password']);
            exit;
        }

        if (isset($user['is_active']) && !$user['is_active']) {
            http_response_code(403);
            echo json_encode(['error' => 'Account is disabled']);
            exit;
        }

        // Update last login (token will be set below)
        $pdo->prepare("UPDATE users SET last_login = NOW() WHERE id = ?")->execute([$user['id']]);

        // Get permissions for user role
        $permissions = [];
        if ($user['role']) {
            try {
                $permStmt = $pdo->prepare("SELECT page_key, can_view, can_create, can_edit, can_delete FROM role_permissions WHERE role = ?");
                $permStmt->execute([$user['role']]);
                $permRows = $permStmt->fetchAll(PDO::FETCH_ASSOC);
                foreach ($permRows as $p) {
                    $permissions[$p['page_key']] = [
                        'view' => (bool) $p['can_view'],
                        'create' => (bool) $p['can_create'],
                        'edit' => (bool) $p['can_edit'],
                        'delete' => (bool) $p['can_delete'],
                    ];
                }
            } catch (PDOException $e) {
                // role_permissions table may not exist on all environments
                $permissions = [];
            }
        }

        // Generate simple token
        $token = bin2hex(random_bytes(32));
        // Store token for single-device enforcement
        try {
            $pdo->prepare("UPDATE users SET remember_token = ? WHERE id = ?")->execute([$token, $user['id']]);
        } catch (Exception $e) { /* ignore */ }
        // Log login activity
        try {
            $stmtLog = $pdo->prepare("INSERT INTO activity_logs (user_id, action, entity_type, ip_address, user_agent, created_at) VALUES (?, 'login', 'user', ?, ?, NOW())");
            $stmtLog->execute([$user['id'], $_SERVER['REMOTE_ADDR'] ?? 'unknown', $_SERVER['HTTP_USER_AGENT'] ?? 'unknown']);
        } catch (Exception $e) { /* ignore */ }

        unset($user['password']);
        echo json_encode([
            'success' => true,
            'user' => $user,
            'permissions' => $permissions,
            'token' => $token,
        ]);
    } catch (PDOException $e) {
        http_response_code(500);
        echo json_encode(['error' => 'Server error']);
    }
    exit;
}

// Role Permissions endpoint - get all permissions for a role
if ($resource === 'permissions' && $method === 'GET') {
    $role = $_GET['role'] ?? '';
    if (empty($role)) {
        http_response_code(400);
        echo json_encode(['error' => 'Role parameter is required']);
        exit;
    }

    try {
        $stmt = $pdo->prepare("SELECT page_key, can_view, can_create, can_edit, can_delete FROM role_permissions WHERE role = ? ORDER BY page_key");
        $stmt->execute([$role]);
        $permissions = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Convert to keyed object for easy lookup
        $permMap = [];
        foreach ($permissions as $p) {
            $permMap[$p['page_key']] = [
                'view' => (bool) $p['can_view'],
                'create' => (bool) $p['can_create'],
                'edit' => (bool) $p['can_edit'],
                'delete' => (bool) $p['can_delete'],
            ];
        }

        echo json_encode(['success' => true, 'data' => $permMap, 'role' => $role]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to fetch permissions: ' . $e->getMessage()]);
    }
    exit;
}

// Bulk save role permissions
if ($resource === 'role-permissions' && $id === 'bulk' && $method === 'POST') {
    $permissions = $input['permissions'] ?? [];
    if (empty($permissions)) {
        http_response_code(400);
        echo json_encode(['error' => 'Permissions array is required']);
        exit;
    }

    try {
        $pdo->beginTransaction();
        $stmt = $pdo->prepare("INSERT INTO role_permissions (role, page_key, can_view, can_create, can_edit, can_delete) 
            VALUES (?, ?, ?, ?, ?, ?) 
            ON DUPLICATE KEY UPDATE can_view = VALUES(can_view), can_create = VALUES(can_create), can_edit = VALUES(can_edit), can_delete = VALUES(can_delete)");

        foreach ($permissions as $perm) {
            $stmt->execute([
                $perm['role'],
                $perm['page_key'],
                $perm['can_view'] ?? 0,
                $perm['can_create'] ?? 0,
                $perm['can_edit'] ?? 0,
                $perm['can_delete'] ?? 0,
            ]);
        }
        $pdo->commit();
        echo json_encode(['success' => true, 'message' => 'Permissions saved', 'count' => count($permissions)]);
    } catch (Exception $e) {
        $pdo->rollBack();
        http_response_code(500);
        echo json_encode(['error' => 'Failed to save permissions: ' . $e->getMessage()]);
    }
    exit;
}

// System Config endpoint for Turret (SIP server, etc.)
if ($resource === 'system-config' && $method === 'GET') {
    try {
        // Check if system_config table exists
        $tableCheck = $pdo->query("SHOW TABLES LIKE 'system_config'");
        if ($tableCheck->rowCount() > 0) {
            $stmt = $pdo->query("SELECT config_key, config_value FROM system_config");
            $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
            echo json_encode(['success' => true, 'data' => $data]);
        } else {
            // Return defaults if table doesn't exist
            echo json_encode([
                'success' => true,
                'data' => [
                    ['config_key' => 'sip_server', 'config_value' => '103.154.80.172'],
                    ['config_key' => 'sip_port', 'config_value' => '5060'],
                    ['config_key' => 'stun_server', 'config_value' => 'stun:stun.l.google.com:19302']
                ]
            ]);
        }
    } catch (Exception $e) {
        // Return defaults on error
        echo json_encode([
            'success' => true,
            'data' => [
                ['config_key' => 'sip_server', 'config_value' => '103.154.80.172'],
                ['config_key' => 'sip_port', 'config_value' => '5060'],
                ['config_key' => 'stun_server', 'config_value' => 'stun:stun.l.google.com:19302']
            ]
        ]);
    }
    exit;
}

// Stats endpoint for dashboard
if ($resource === 'stats' && $method === 'GET') {
    // Helper function to get active/inactive counts
    function getStats($pdo, $table)
    {
        try {
            // Check if table exists
            $check = $pdo->query("SHOW TABLES LIKE '$table'");
            if ($check->rowCount() === 0) {
                return ['active' => 0, 'inactive' => 0];
            }

            // Check if is_active column exists
            $cols = $pdo->query("SHOW COLUMNS FROM `$table` LIKE 'is_active'");
            if ($cols->rowCount() > 0) {
                $active = $pdo->query("SELECT COUNT(*) FROM `$table` WHERE is_active = 1")->fetchColumn() ?: 0;
                $inactive = $pdo->query("SELECT COUNT(*) FROM `$table` WHERE is_active = 0")->fetchColumn() ?: 0;
            } else {
                // No is_active column, count all as active
                $active = $pdo->query("SELECT COUNT(*) FROM `$table`")->fetchColumn() ?: 0;
                $inactive = 0;
            }
            return ['active' => (int) $active, 'inactive' => (int) $inactive];
        } catch (Exception $e) {
            return ['active' => 0, 'inactive' => 0];
        }
    }

    try {
        $stats = [
            // Row 1: Organization
            'ho' => getStats($pdo, 'head_offices'),
            'branch' => getStats($pdo, 'branches'),
            'subBranch' => getStats($pdo, 'sub_branches'),
            'callServer' => getStats($pdo, 'call_servers'),

            // Row 2: Line
            'line' => getStats($pdo, 'lines'),
            'extension' => getStats($pdo, 'extensions'),
            'privateWire' => getStats($pdo, 'private_wires'),
            'cas' => getStats($pdo, 'cas'),
            'intercom' => getStats($pdo, 'intercoms'),

            // Row 3: Trunk/Routing
            'trunk' => getStats($pdo, 'trunks'),
            'inbound' => getStats($pdo, 'inbound_routings'),
            'outbound' => getStats($pdo, 'outbound_routings'),
            'conference' => getStats($pdo, 'conferences'),

            // Row 4: SBC
            'sbc' => getStats($pdo, 'sbcs'),
            'sbcConnection' => getStats($pdo, 'sbc_connections'),
            'sbcRouting' => getStats($pdo, 'sbc_routes'),
            'sipThirdParty' => getStats($pdo, 'device_3rd_parties'),

            // Row 5: Device
            'turret' => getStats($pdo, 'turret_devices'),
            'webDevice' => getStats($pdo, 'web_devices'),
            'thirdPartyDevice' => getStats($pdo, 'device_3rd_parties'),

            // Row 6: Voice Gateway
            'analogFxoGateway' => getStats($pdo, 'analog_fxo_gateways'),
            'analogFxsGateway' => getStats($pdo, 'analog_fxs_gateways'),
            'e1Gateway' => getStats($pdo, 'e1_gateways'),
            'e1CasGateway' => getStats($pdo, 'e1_cas_gateways'),

            // Row 7: Recording & Alarm
            'recordingServer' => getStats($pdo, 'recording_servers'),
            'recordingChannel' => getStats($pdo, 'recording_channels'),
            'alarmNotification' => getStats($pdo, 'alarm_notifications'),
        ];
        echo json_encode(['success' => true, 'data' => $stats]);
    } catch (Exception $e) {
        // Return empty stats on error
        echo json_encode(['success' => true, 'data' => []]);
    }
    exit;
}

// Usage Report endpoint for call statistics per extension
if ($resource === 'usage-report' && $method === 'GET') {
    try {
        $date = $_GET['date'] ?? date('Y-m-d');
        $branchId = $_GET['branch_id'] ?? null;
        $callServerId = $_GET['call_server_id'] ?? null;

        $where = "WHERE u.date = ?";
        $params = [$date];

        if ($branchId) {
            $where .= " AND u.branch_id = ?";
            $params[] = $branchId;
        }

        if ($callServerId) {
            $where .= " AND u.call_server_id = ?";
            $params[] = $callServerId;
        }

        $sql = "SELECT 
            u.*,
            b.name as branch_name,
            cs.name as call_server_name,
            cs.host as ip_address
        FROM usage_statistics u
        LEFT JOIN branches b ON u.branch_id = b.id
        LEFT JOIN call_servers cs ON u.call_server_id = cs.id
        $where
        ORDER BY u.extension_number ASC";

        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        $data = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Format total_time as HH:MM:SS
        foreach ($data as &$row) {
            $row['total_time_inbound_formatted'] = gmdate("H:i:s", $row['total_time_inbound'] ?? 0);
            $row['total_time_outbound_formatted'] = gmdate("H:i:s", $row['total_time_outbound'] ?? 0);
        }

        // Get filter options
        $branches = $pdo->query("SELECT id, name FROM branches ORDER BY name")->fetchAll(PDO::FETCH_ASSOC);
        $callServers = $pdo->query("SELECT id, name, host FROM call_servers ORDER BY name")->fetchAll(PDO::FETCH_ASSOC);

        echo json_encode([
            'success' => true,
            'data' => $data,
            'filters' => [
                'branches' => $branches,
                'call_servers' => $callServers
            ],
            'meta' => [
                'date' => $date,
                'total_records' => count($data)
            ]
        ]);
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'error' => $e->getMessage(), 'data' => []]);
    }
    exit;
}


// SBC Status Monitor - list all SBCs with connection status
if ($resource === 'sbc-status' && $id === null && $method === 'GET') {
    try {
        $query = "SELECT s.*, cs.name as call_server_name FROM sbcs s LEFT JOIN call_servers cs ON s.call_server_id = cs.id";
        $params = [];
        if (isset($_GET['call_server_id']) && $_GET['call_server_id']) {
            $query .= " WHERE s.call_server_id = ?";
            $params[] = $_GET['call_server_id'];
        }
        $stmt = $pdo->prepare($query);
        $stmt->execute($params);
        $sbcs = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $results = [];
        foreach ($sbcs as $sbc) {
            // Get latest connection status from sbc_connection_status table
            $connStmt = $pdo->prepare("SELECT * FROM sbc_connection_status WHERE sbc_id = ? ORDER BY id DESC LIMIT 1");
            $connStmt->execute([$sbc['id']]);
            $connRow = $connStmt->fetch(PDO::FETCH_ASSOC);
            $host = $sbc['sip_server'] ?? null;
            $port = $sbc['sip_server_port'] ?? 5060;
            if ($connRow) {
                $results[] = array_merge($connRow, [
                    'sbc_name' => $sbc['name'] ?? null,
                    'ip_address' => $host,
                    'port' => $port,
                    'call_server_name' => $sbc['call_server_name'] ?? null,
                ]);
            } else {
                $results[] = [
                    'id' => null,
                    'sbc_id' => $sbc['id'],
                    'sbc_name' => $sbc['name'] ?? null,
                    'ip_address' => $host,
                    'port' => $port,
                    'call_server_name' => $sbc['call_server_name'] ?? null,
                    'peer_name' => $sbc['name'] ?? null,
                    'peer_type' => 'SIP_PEER',
                    'remote_address' => ($host ? $host . ':' . $port : null),
                    'registration_status' => ($sbc['registration'] === 'register' ? 'NOT_REGISTERED' : 'N/A'),
                    'connection_status' => 'UNKNOWN',
                    'latency_ms' => null,
                    'active_calls' => 0,
                    'max_calls' => $sbc['maxchans'] ?? null,
                    'last_activity' => null,
                ];
            }
        }
        echo json_encode(['data' => $results, 'total' => count($results)]);
    } catch (Exception $e) {
        echo json_encode(['data' => [], 'total' => 0, 'error' => $e->getMessage()]);
    }
    exit;
}


// SBC Status Monitor - Realtime via Asterisk AMI
if (preg_match('/^sbc-status\/(\d+)$/', $resource . '/' . $id, $matches)) {
    $sbcId = $matches[1];
    try {
        $stmt = $pdo->prepare("SELECT * FROM sbcs WHERE id = ?");
        $stmt->execute([$sbcId]);
        $sbc = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$sbc) {
            echo json_encode(['data' => [], 'total' => 0]);
            exit;
        }

        $endpointName = 'sbc-' . $sbcId;
        $sipServer = $sbc['sip_server'] ?? 'N/A';
        $sipPort   = $sbc['sip_server_port'] ?? 5060;
        $maxCalls  = $sbc['maxchans'] ?? null;

        $result = [
            'id'                  => (int)$sbcId,
            'sbc_id'              => (int)$sbcId,
            'peer_name'           => $sbc['name'],
            'peer_type'           => 'ITSP',
            'remote_address'      => $sipServer . ':' . $sipPort,
            'local_user'          => null,
            'registration_status' => 'NOT_REGISTERED',
            'connection_status'   => 'UNKNOWN',
            'latency_ms'          => null,
            'active_calls'        => 0,
            'max_calls'           => $maxCalls,
            'last_activity'       => date('Y-m-d H:i:s'),
        ];

        // Query Asterisk AMI for realtime status
        try {
            $ami = @fsockopen('127.0.0.1', 5038, $errno, $errstr, 3);
            if ($ami) {
                stream_set_timeout($ami, 5);
                fgets($ami, 256); // Read greeting

                fputs($ami, "Action: Login\r\nUsername: smartcms\r\nSecret: smartcms_ami_secret_2026\r\n\r\n");
                $buf = ''; $t = microtime(true) + 4;
                while (!feof($ami) && microtime(true) < $t) {
                    $buf .= fgets($ami, 512);
                    if (substr_count($buf, "\r\n\r\n") >= 1) break;
                }

                // pjsip show contacts -> RTT and status for this endpoint
                fputs($ami, "Action: Command\r\nCommand: pjsip show contacts\r\nActionID: c1\r\n\r\n");
                $out = ''; $t = microtime(true) + 5;
                while (!feof($ami) && microtime(true) < $t) {
                    $out .= fgets($ami, 4096);
                    if (strpos($out, '--END COMMAND--') !== false) break;
                }
                foreach (explode("\n", $out) as $line) {
                    if (strpos($line, $endpointName . '/') !== false) {
                        if (preg_match('/\s+(Avail|Unavail|NonQual|Unmonitored)\s+([\d.nan]+)/', $line, $m)) {
                            $status = $m[1]; $rtt = floatval($m[2]);
                            if ($status === 'Avail') {
                                $result['connection_status'] = 'OK';
                                $result['latency_ms'] = round($rtt, 2);
                            } elseif ($status === 'Unavail') {
                                $result['connection_status'] = 'UNREACHABLE';
                            } else {
                                $result['connection_status'] = 'UNKNOWN';
                            }
                        } elseif (strpos($line, 'NonQual') !== false) {
                            $result['connection_status'] = 'UNKNOWN';
                        } elseif (strpos($line, 'Unavail') !== false) {
                            $result['connection_status'] = 'UNREACHABLE';
                        }
                        break;
                    }
                }

                // core show channels -> count active channels for this endpoint
                fputs($ami, "Action: Command\r\nCommand: core show channels verbose\r\nActionID: c2\r\n\r\n");
                $chOut = ''; $t = microtime(true) + 5;
                while (!feof($ami) && microtime(true) < $t) {
                    $chOut .= fgets($ami, 4096);
                    if (strpos($chOut, '--END COMMAND--') !== false) break;
                }
                $activeCalls = 0;
                foreach (explode("\n", $chOut) as $line) {
                    if (strpos($line, 'PJSIP/' . $endpointName . '-') !== false) $activeCalls++;
                }
                $result['active_calls'] = $activeCalls;

                fputs($ami, "Action: Logoff\r\n\r\n");
                fclose($ami);
            }
        } catch (Exception $amiEx) { /* AMI unavailable, use defaults */ }

        echo json_encode(['data' => [$result], 'total' => 1]);
    } catch (Exception $e) {
        echo json_encode(['data' => [], 'total' => 0, 'error' => $e->getMessage()]);
    }
    exit;
}



// Topology endpoint - generate network diagram data from real database
if ($resource === 'topology' && $method === 'GET') {
    $companyId = $_GET['company_id'] ?? null;

    try {
        $nodes = [];
        $edges = [];

        // Build WHERE clause for company filter
        $hoWhere = "WHERE ho.is_active = 1";
        $hoParams = [];
        if ($companyId) {
            $hoWhere .= " AND ho.customer_id = ?";
            $hoParams[] = $companyId;
        }

        // Get head offices with call server info
        $hoSql = "SELECT 
            ho.id, ho.name, ho.code, ho.type, ho.city,
            ho.customer_id, c.name as company_name,
            GROUP_CONCAT(DISTINCT cs.host SEPARATOR ', ') as ips
        FROM head_offices ho
        LEFT JOIN customers c ON ho.customer_id = c.id
        LEFT JOIN call_servers cs ON cs.head_office_id = ho.id AND cs.is_active = 1
        $hoWhere
        GROUP BY ho.id
        ORDER BY ho.name";

        $stmt = $pdo->prepare($hoSql);
        $stmt->execute($hoParams);
        $headOffices = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Add head office nodes
        foreach ($headOffices as $ho) {
            $nodes[] = [
                'id' => 'ho_' . $ho['id'],
                'label' => $ho['name'],
                'title' => $ho['name'] . ' (' . ($ho['company_name'] ?? 'N/A') . ')',
                'group' => 'headoffice',
                'status' => 'OK',
                'ip' => $ho['ips'] ?? 'N/A',
                'has_sbc' => false
            ];
        }

        // Get branches with SBC info
        $brWhere = "WHERE b.is_active = 1";
        $brParams = [];
        if ($companyId) {
            $brWhere .= " AND b.customer_id = ?";
            $brParams[] = $companyId;
        }

        // Check if sbc_id column exists in branches table
        $sbcColumnExists = false;
        try {
            $colCheck = $pdo->query("SHOW COLUMNS FROM branches LIKE 'sbc_id'");
            $sbcColumnExists = $colCheck->rowCount() > 0;
        } catch (Exception $e) {
            // Column doesn't exist, continue without it
        }

        if ($sbcColumnExists) {
            $brSql = "SELECT 
                b.id, b.name, b.code, b.head_office_id, b.customer_id,
                b.call_server_id, b.sbc_id,
                cs.host as ip,
                c.name as company_name,
                sbc.name as sbc_name
            FROM branches b
            LEFT JOIN customers c ON b.customer_id = c.id
            LEFT JOIN call_servers cs ON b.call_server_id = cs.id
            LEFT JOIN call_servers sbc ON b.sbc_id = sbc.id
            $brWhere
            ORDER BY b.name";
        } else {
            $brSql = "SELECT 
                b.id, b.name, b.code, b.head_office_id, b.customer_id,
                b.call_server_id, NULL as sbc_id,
                cs.host as ip,
                c.name as company_name,
                NULL as sbc_name
            FROM branches b
            LEFT JOIN customers c ON b.customer_id = c.id
            LEFT JOIN call_servers cs ON b.call_server_id = cs.id
            $brWhere
            ORDER BY b.name";
        }

        $stmt = $pdo->prepare($brSql);
        $stmt->execute($brParams);
        $branches = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Add branch nodes and edges
        foreach ($branches as $br) {
            $hasSbc = !empty($br['sbc_id']);

            $nodes[] = [
                'id' => 'br_' . $br['id'],
                'label' => $br['name'],
                'title' => $br['name'] . ' (' . ($br['company_name'] ?? 'N/A') . ')',
                'group' => 'branch',
                'status' => 'OK',
                'ip' => $br['ip'] ?? 'N/A',
                'has_sbc' => $hasSbc
            ];

            // Create edge to head office if linked
            if ($br['head_office_id']) {
                $edges[] = [
                    'from' => 'ho_' . $br['head_office_id'],
                    'to' => 'br_' . $br['id'],
                    'label' => '',
                    'color' => '#22c55e' // green for active
                ];
            }
        }


        // ---- CALL SERVERS (standalone nodes) ----
        $nodeTrack=[];
        foreach ($nodes as $nd) $nodeTrack[$nd['id']]=true;
        try {
            $csAll2=$pdo->query('SELECT * FROM call_servers WHERE is_active=1')->fetchAll(PDO::FETCH_ASSOC);
            foreach ($csAll2 as $cs) {
                $csnid='cs_'.$cs['id'];
                if (isset($nodeTrack[$csnid])) continue;
                $csIp=$cs['host']??'N/A'; $csPort=$cs['port']??5060;
                $nodes[]=['id'=>$csnid,'label'=>$cs['name'].chr(10).'IP: '.$csIp,'title'=>'Call Server: '.$cs['name'].chr(10).'IP: '.$csIp.':'.$csPort,'group'=>($cs['type']==='sbc')?'sbc':'callserver','ip'=>$csIp];
                $nodeTrack[$csnid]=true;
            }
        } catch (Exception $e) {}
        // ---- TRUNKS ----
        try {
            $trs2=$pdo->query('SELECT id,name,sip_server,sip_server_port,call_server_id FROM trunks')->fetchAll(PDO::FETCH_ASSOC);
            foreach ($trs2 as $tr) {
                $tnid='trunk_'.$tr['id']; if (isset($nodeTrack[$tnid])) continue;
                $tip=$tr['sip_server']??'N/A'; $tport=$tr['sip_server_port']??5060;
                $tiplbl=($tip&&$tip!=='N/A')?$tip.':'.$tport:'N/A';
                $nodes[]=['id'=>$tnid,'label'=>'trunk-'.$tr['id'].chr(10).$tr['name'].chr(10).'IP: '.$tiplbl,'title'=>'Trunk: '.$tr['name'].chr(10).'IP: '.$tiplbl,'group'=>'trunk','ip'=>$tip];
                $nodeTrack[$tnid]=true;
                if ($tr['call_server_id']) $edges[]=['from'=>'cs_'.$tr['call_server_id'],'to'=>$tnid,'label'=>'trunk','color'=>'#f59e0b'];
            }
        } catch (Exception $e) {}
        // ---- SBCS ----
        try {
            $sbcrows2=$pdo->query('SELECT * FROM sbcs')->fetchAll(PDO::FETCH_ASSOC);
            foreach ($sbcrows2 as $sbc) {
                $snid='sbc_'.$sbc['id']; if (isset($nodeTrack[$snid])) continue;
                $sip=$sbc['sip_server']??'N/A'; $sport=$sbc['sip_server_port']??5060;
                $siplbl=($sip&&$sip!=='N/A')?$sip.':'.$sport:'N/A';
                $nodes[]=['id'=>$snid,'label'=>'sbc-'.$sbc['id'].chr(10).$sbc['name'].chr(10).'IP: '.$siplbl,'title'=>'SBC: '.$sbc['name'].chr(10).'IP: '.$siplbl,'group'=>'sbc','ip'=>$sip];
                $nodeTrack[$snid]=true;
                if (!empty($sbc['call_server_id'])) $edges[]=['from'=>'cs_'.$sbc['call_server_id'],'to'=>$snid,'label'=>'SBC','color'=>'#8b5cf6'];
            }
        } catch (Exception $e) {}
        // ---- SBC BRIDGE ROUTES ----
        try {
            $rtrows2=$pdo->query('SELECT * FROM sbc_routes WHERE src_is_active=1 LIMIT 50')->fetchAll(PDO::FETCH_ASSOC);
            foreach ($rtrows2 as $rt) {
                $fn=$rt['src_from_sbc_id']?'sbc_'.$rt['src_from_sbc_id']:'trunk_'.$rt['src_destination_id'];
                $tn=$rt['dest_from_sbc_id']?'sbc_'.$rt['dest_from_sbc_id']:'trunk_'.$rt['dest_destination_id'];
                if (isset($nodeTrack[$fn])&&isset($nodeTrack[$tn])) $edges[]=['from'=>$fn,'to'=>$tn,'label'=>'bridge','color'=>'#22c55e','dashes'=>true];
            }
        } catch (Exception $e) {}
        // Get companies for filter dropdown
        $companies = $pdo->query("SELECT id, name, code FROM customers WHERE is_active = 1 ORDER BY name")->fetchAll(PDO::FETCH_ASSOC);

        echo json_encode([
            'success' => true,
            'data' => [
                'nodes' => $nodes,
                'edges' => $edges
            ],
            'filters' => [
                'companies' => $companies
            ],
            'meta' => [
                'total_nodes' => count($nodes),
                'total_edges' => count($edges),
                'company_id' => $companyId
            ]
        ]);
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'error' => $e->getMessage(), 'data' => ['nodes' => [], 'edges' => []]]);
    }
    exit;
}

// Dropdowns endpoint for select options
if ($resource === 'dropdowns' && $method === 'GET') {
    $type = $_GET['type'] ?? '';
    $data = [];

    try {
        switch ($type) {
            case 'recordings':
                $stmt = $pdo->query("SELECT id, name, filename FROM recordings ORDER BY name");
                $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
                break;
            case 'announcements':
                $stmt = $pdo->query("SELECT id, name, filename FROM announcements ORDER BY name");
                $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
                break;
            case 'call-servers':
                $stmt = $pdo->query("SELECT id, name FROM call_servers ORDER BY name");
                $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
                break;
            case 'extensions':
                $stmt = $pdo->query("SELECT id, extension_number as name FROM extensions ORDER BY extension_number");
                $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
                break;
            case 'ivr':
                $stmt = $pdo->query("SELECT id, name FROM ivr ORDER BY name");
                $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
                break;
            default:
                $data = [];
        }
        echo json_encode(['success' => true, 'data' => $data]);
    } catch (Exception $e) {
        echo json_encode(['success' => true, 'data' => []]);
    }
    exit;
}


// Upload avatar endpoint
if ($resource === 'upload-avatar' && $method === 'POST') {
    $userId = $input['user_id'] ?? $_GET['user_id'] ?? null;
    $imageData = $input['image'] ?? null;

    if (!$userId || !$imageData) {
        http_response_code(400);
        echo json_encode(['error' => 'user_id and image are required']);
        exit;
    }

    if (!preg_match('/^data:image\/([a-zA-Z0-9+.-]+);base64,/', $imageData, $typeMatch)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid image format, must be base64 data URI']);
        exit;
    }

    $rawData = substr($imageData, strpos($imageData, ',') + 1);
    $decoded = base64_decode($rawData);
    if ($decoded === false) {
        http_response_code(400);
        echo json_encode(['error' => 'Failed to decode image']);
        exit;
    }

    $ext = strtolower($typeMatch[1]);
    if ($ext === 'jpeg') $ext = 'jpg';
    if ($ext === 'svg+xml') $ext = 'svg';
    if (!in_array($ext, ['jpg', 'png', 'gif', 'webp', 'svg'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Unsupported image type: ' . $ext]);
        exit;
    }

    $uploadDir = __DIR__ . '/avatars/';
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0755, true);
    }

    $filename = 'avatar_' . $userId . '_' . time() . '.' . $ext;
    $filepath = $uploadDir . $filename;

    if (file_put_contents($filepath, $decoded) === false) {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to save image']);
        exit;
    }

    try {
        $stmt = $pdo->prepare("UPDATE users SET profile_image = ? WHERE id = ?");
        $stmt->execute([$filename, $userId]);
        // Log profile photo update
        try {
            $__ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $__ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);
            $__l = $pdo->prepare("INSERT INTO `activity_logs` (user_id, action, entity_type, entity_id, ip_address, user_agent, new_values) VALUES (?, 'updated', 'users', ?, ?, ?, ?)");
            $__l->execute([$userId, $userId, $__ip, $__ua, json_encode(['profile_image' => $filename])]);
        } catch (Exception $__e) {}
        echo json_encode(['success' => true, 'filename' => $filename, 'url' => '/api/v1/avatar/' . $filename, 'profile_image' => '/api/v1/avatar/' . $filename]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => 'DB update failed: ' . $e->getMessage()]);
    }
    exit;
}

// Serve avatar image
if ($resource === 'avatar' && $id && ($method === 'GET' || $method === 'HEAD')) {
    header_remove('Content-Type');

    $filename = basename($id);
    $uploadDir = __DIR__ . '/avatars/';
    $filepath = $uploadDir . $filename;

    if (!file_exists($filepath)) {
        header('Content-Type: application/json');
        http_response_code(404);
        echo json_encode(['error' => 'Avatar not found']);
        exit;
    }

    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $mimeTypes = [
        'jpg'  => 'image/jpeg',
        'jpeg' => 'image/jpeg',
        'png'  => 'image/png',
        'gif'  => 'image/gif',
        'webp' => 'image/webp',
        'svg'  => 'image/svg+xml',
    ];
    $mime = $mimeTypes[$ext] ?? 'application/octet-stream';
    header('Content-Type: ' . $mime);
    header('Content-Length: ' . filesize($filepath));
    header('Cache-Control: public, max-age=86400');
    readfile($filepath);
    exit;
}

// Get current user profile endpoint
if ($resource === 'me' && $method === 'GET') {
    // Validate by Bearer token only — no user_id required
    // This enables single-device enforcement: new login overwrites token in DB
    $headers = function_exists('getallheaders') ? getallheaders() : [];
    $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? $_SERVER['HTTP_AUTHORIZATION'] ?? '';

    if (!preg_match('/Bearer\s+(.+)/i', $authHeader, $tokenMatches)) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized', 'reason' => 'no_token']);
        exit;
    }

    $bearerToken = trim($tokenMatches[1]);

    try {
        $stmt = $pdo->prepare("SELECT id, name, email, role, profile_image, is_active, last_login FROM users WHERE remember_token = ?");
        $stmt->execute([$bearerToken]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            http_response_code(401);
            echo json_encode(["error" => "Session expired. Please login again.", "code" => "TOKEN_INVALID"]);
            exit;
        }

        echo json_encode(['success' => true, 'data' => $user]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to fetch user']);
    }
    exit;
}


// Logout endpoint
if ($resource === 'logout' && $method === 'POST') {
    $email = $input['email'] ?? '';
    $name = $input['name'] ?? '';
    $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';

    $userId = $input['user_id'] ?? $_SERVER['HTTP_X_USER_ID'] ?? null;

    // Clear remember_token (single-device logout)
    if ($userId) {
        try {
            $pdo->prepare("UPDATE users SET remember_token = NULL WHERE id = ?")->execute([$userId]);
        } catch (Exception $e) { /* ignore */ }
    }

    // Log logout activity
    try {
        $logStmt = $pdo->prepare("INSERT INTO `activity_logs` (user_id, action, entity_type, ip_address, user_agent, new_values) VALUES (?, 'logout', 'auth', ?, ?, ?)");
        $logStmt->execute([$userId, $ip_address, $user_agent, json_encode(['email' => $email, 'name' => $name])]);
    } catch (Exception $e) { /* ignore */ }

    echo json_encode(['success' => true, 'message' => 'Logged out successfully']);
    exit;
}

// [Old simple topology removed - handled by comprehensive topology above]

// ============================================================
// BACKUP & RESTORE API  (v2.0 — module-based)
// ============================================================
if ($resource === 'backup') {
    // Auth: require valid token + admin/super_admin role
    $bkHeaders = getallheaders();
    $bkAuthH = $bkHeaders['Authorization'] ?? $bkHeaders['authorization'] ?? $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    $bkUser = null;
    if (preg_match('/Bearer\s+(.+)/i', $bkAuthH, $bkTok)) {
        $bkStmt = $pdo->prepare("SELECT id, name, role FROM users WHERE remember_token = ? AND is_active = 1");
        $bkStmt->execute([trim($bkTok[1])]);
        $bkUser = $bkStmt->fetch(PDO::FETCH_ASSOC);
    }
    if (!$bkUser) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        exit;
    }
    if (!in_array($bkUser['role'], ['super_admin', 'admin'])) {
        http_response_code(403);
        echo json_encode(['error' => 'Forbidden: admin or super_admin required']);
        exit;
    }

    $bkDir = '/opt/smartcms/backup';
    if (!is_dir($bkDir)) { mkdir($bkDir, 0755, true); }

    $action   = $id;
    $subParam = $parts[2] ?? null;

    // Module => DB table mapping
    $moduleTableMap = [
        'extensions'   => ['extensions', 'lines', 'vpws', 'cas', 'intercoms', 'device_3rd_parties'],
        'trunks'       => ['trunks'],
        'sbc'          => ['sbcs', 'sbc_routes', 'sbc_connection_status'],
        'routing'      => ['inbound_routings', 'outbound_routings', 'outbound_dial_patterns'],
        'organization' => ['head_offices', 'branches', 'sub_branches'],
        'users'        => ['users', 'cms_policies', 'activity_logs'],
        'call_servers' => ['call_servers'],
    ];
    $fileModules = ['system_config', 'uploads'];
    $allModules  = array_merge(array_keys($moduleTableMap), $fileModules);

    // Validate backup filename: backup-YYYYMMDD-HHmmss.tar.gz
    $validateFilename = function($fn) {
        return (bool)preg_match('/^backup-\d{8}-\d{6}\.tar\.gz$/', $fn);
    };

    // ---- GET /v1/backup/list ----
    if ($action === 'list' && $method === 'GET') {
        $files = glob($bkDir . '/backup-*.tar.gz') ?: [];
        $list  = [];
        foreach ($files as $file) {
            $fn    = basename($file);
            $size  = filesize($file);
            $mtime = filemtime($file);
            $info  = null;
            $infoJson = shell_exec("tar -xzf " . escapeshellarg($file) . " -O ./backup-info.json 2>/dev/null");
            if ($infoJson) { $info = json_decode($infoJson, true); }
            $list[] = [
                'filename'   => $fn,
                'size_bytes' => $size,
                'size_human' => round($size / 1024 / 1024, 2) . ' MB',
                'created_at' => date('Y-m-d H:i:s', $mtime),
                'info'       => $info,
            ];
        }
        usort($list, fn($a, $b) => strcmp($b['created_at'], $a['created_at']));
        echo json_encode(['data' => $list]);
        exit;
    }

    // ---- POST /v1/backup/create ----
    if ($action === 'create' && $method === 'POST') {
        $bkName     = isset($input['name'])        && $input['name']        !== '' ? trim($input['name'])        : null;
        $bkDesc     = isset($input['description']) && $input['description'] !== '' ? trim($input['description']) : '';
        $modulesSel = $input['modules'] ?? null;

        // Resolve selected modules
        if ($modulesSel === null) {
            $selectedModules = $allModules;
        } else {
            $selectedModules = [];
            foreach ($allModules as $m) {
                if (!empty($modulesSel[$m])) $selectedModules[] = $m;
            }
        }
        if (empty($selectedModules)) {
            http_response_code(400);
            echo json_encode(['error' => 'No modules selected']);
            exit;
        }

        $ts     = date('Ymd-His');
        $tmpDir = "/tmp/smartcms-backup-$ts";
        mkdir($tmpDir,           0755, true);
        mkdir("$tmpDir/modules", 0755, true);

        $moduleInfo = [];

        // --- DB modules ---
        foreach ($moduleTableMap as $modName => $tables) {
            if (!in_array($modName, $selectedModules)) continue;
            $existingTables = [];
            $recordCounts   = [];
            foreach ($tables as $t) {
                try {
                    $cnt = $pdo->query("SELECT COUNT(*) FROM `$t`")->fetchColumn();
                    $existingTables[] = $t;
                    $recordCounts[$t] = (int)$cnt;
                } catch (Exception $e) {}
            }
            if (!empty($existingTables)) {
                $tableArgs = implode(' ', array_map('escapeshellarg', $existingTables));
                exec("mysqldump -u asterisk -pMaja1234! --single-transaction --quick db_ucx $tableArgs > "
                    . escapeshellarg("$tmpDir/modules/$modName.sql") . " 2>/dev/null");
            }
            $moduleInfo[$modName] = [
                'included'      => true,
                'tables'        => $existingTables,
                'record_counts' => $recordCounts,
            ];
        }

        // --- system_config module ---
        if (in_array('system_config', $selectedModules)) {
            $scDir = "$tmpDir/modules/system_config";
            mkdir($scDir, 0755, true);
            exec("cp -r /etc/smartcms-asterisk/. " . escapeshellarg($scDir) . "/ 2>/dev/null");
            exec("find " . escapeshellarg($scDir) . " -name '*.bak*' -delete 2>/dev/null");
            $configFiles = array_values(array_map('basename', glob("$scDir/*.conf") ?: []));
            $moduleInfo['system_config'] = ['included' => true, 'files' => $configFiles];
        }

        // --- uploads module ---
        if (in_array('uploads', $selectedModules)) {
            $avatarSrc = '/opt/smartcms/backend/storage/avatars';
            if (is_dir($avatarSrc)) {
                $uplDir = "$tmpDir/modules/uploads/avatars";
                mkdir($uplDir, 0755, true);
                exec("cp -r " . escapeshellarg($avatarSrc) . "/. " . escapeshellarg($uplDir) . "/ 2>/dev/null");
                $filesCount = count(glob("$uplDir/*") ?: []);
            } else {
                $filesCount = 0;
            }
            $moduleInfo['uploads'] = ['included' => true, 'files_count' => $filesCount];
        }

        // --- backup-info.json v2.0 ---
        $bkInfo = [
            'version'     => '2.0',
            'name'        => $bkName ?: ('Backup ' . date('Y-m-d H:i')),
            'description' => $bkDesc,
            'created_at'  => date('Y-m-d H:i:s'),
            'created_by'  => $bkUser['name'],
            'server_ip'   => '103.154.80.173',
            'modules'     => $moduleInfo,
        ];
        file_put_contents("$tmpDir/backup-info.json", json_encode($bkInfo, JSON_PRETTY_PRINT));

        // --- Create tar.gz ---
        $tarFile = "$bkDir/backup-$ts.tar.gz";
        exec("tar czf " . escapeshellarg($tarFile) . " -C " . escapeshellarg($tmpDir) . " . 2>/dev/null", $tarOut, $tarRc);
        exec("rm -rf " . escapeshellarg($tmpDir));

        if ($tarRc !== 0 || !file_exists($tarFile)) {
            http_response_code(500);
            echo json_encode(['error' => 'Failed to create backup archive']);
            exit;
        }

        $size = filesize($tarFile);
        try {
            $pdo->prepare("INSERT INTO activity_logs (user_id, action, entity_type, ip_address, user_agent, new_values, created_at) VALUES (?, 'created', 'backup', ?, ?, ?, NOW())")
                ->execute([$bkUser['id'], $_SERVER['REMOTE_ADDR'] ?? 'unknown', substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255), json_encode(['filename' => basename($tarFile), 'modules' => array_keys($moduleInfo)])]);
        } catch (Exception $e) {}

        echo json_encode([
            'success'    => true,
            'filename'   => basename($tarFile),
            'name'       => $bkInfo['name'],
            'size_bytes' => $size,
            'size_human' => round($size / 1024 / 1024, 2) . ' MB',
            'created_at' => date('Y-m-d H:i:s'),
            'modules'    => array_keys($moduleInfo),
        ]);
        exit;
    }

    // ---- GET /v1/backup/download/{filename} ----
    if ($action === 'download' && $subParam && $method === 'GET') {
        if (!$validateFilename($subParam)) {
            http_response_code(400); echo json_encode(['error' => 'Invalid filename']); exit;
        }
        $filePath = "$bkDir/$subParam";
        if (!file_exists($filePath)) {
            http_response_code(404); echo json_encode(['error' => 'Backup file not found']); exit;
        }
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . $subParam . '"');
        header('Content-Length: ' . filesize($filePath));
        header('Cache-Control: no-cache');
        readfile($filePath);
        exit;
    }

    // ---- DELETE /v1/backup/{filename} ----
    $reservedActions = ['list', 'create', 'download', 'restore', 'restore-selective'];
    if ($action && !in_array($action, $reservedActions) && $method === 'DELETE') {
        if (!$validateFilename($action)) {
            http_response_code(400); echo json_encode(['error' => 'Invalid filename']); exit;
        }
        $filePath = "$bkDir/$action";
        if (!file_exists($filePath)) {
            http_response_code(404); echo json_encode(['error' => 'Backup file not found']); exit;
        }
        unlink($filePath);
        try {
            $pdo->prepare("INSERT INTO activity_logs (user_id, action, entity_type, ip_address, user_agent, new_values, created_at) VALUES (?, 'deleted', 'backup', ?, ?, ?, NOW())")
                ->execute([$bkUser['id'], $_SERVER['REMOTE_ADDR'] ?? 'unknown', substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255), json_encode(['filename' => $action])]);
        } catch (Exception $e) {}
        echo json_encode(['success' => true]);
        exit;
    }

    // ---- POST /v1/backup/restore OR restore-selective ----
    if (in_array($action, ['restore', 'restore-selective']) && $method === 'POST') {
        $ts     = date('Ymd-His');
        $tmpDir = "/tmp/smartcms-restore-$ts";
        mkdir($tmpDir, 0755, true);

        $uploadedFile = null;
        if (!empty($_FILES['backup']['tmp_name'])) {
            $uploadedFile = $_FILES['backup']['tmp_name'];
        } elseif (!empty($input['filename'])) {
            if (!$validateFilename($input['filename'])) {
                exec("rm -rf " . escapeshellarg($tmpDir));
                http_response_code(400); echo json_encode(['error' => 'Invalid filename']); exit;
            }
            $uploadedFile = "$bkDir/{$input['filename']}";
        }

        if (!$uploadedFile || !file_exists($uploadedFile)) {
            exec("rm -rf " . escapeshellarg($tmpDir));
            http_response_code(400); echo json_encode(['error' => 'No backup file provided']); exit;
        }

        exec("tar xzf " . escapeshellarg($uploadedFile) . " -C " . escapeshellarg($tmpDir) . " 2>&1", $extOut, $extRc);
        if ($extRc !== 0) {
            exec("rm -rf " . escapeshellarg($tmpDir));
            http_response_code(500); echo json_encode(['error' => 'Failed to extract backup']); exit;
        }

        $infoFile = "$tmpDir/backup-info.json";
        if (!file_exists($infoFile)) {
            exec("rm -rf " . escapeshellarg($tmpDir));
            http_response_code(400); echo json_encode(['error' => 'Invalid backup: missing backup-info.json']); exit;
        }

        $backupInfo = json_decode(file_get_contents($infoFile), true);
        $bkVersion  = $backupInfo['version'] ?? '1.0';

        if (!$backupInfo || !in_array($bkVersion, ['1.0', '2.0'])) {
            exec("rm -rf " . escapeshellarg($tmpDir));
            http_response_code(400); echo json_encode(['error' => 'Incompatible backup version']); exit;
        }

        $restored = [];

        if ($bkVersion === '2.0') {
            // ---- v2.0 module restore ----
            $availableModules = array_keys($backupInfo['modules'] ?? []);
            $selectedModules  = $input['modules'] ?? $availableModules;
            $toRestore        = array_intersect($selectedModules, $availableModules);

            foreach ($toRestore as $mod) {
                if (empty($backupInfo['modules'][$mod]['included'])) continue;

                if (isset($moduleTableMap[$mod])) {
                    $sqlFile = "$tmpDir/modules/$mod.sql";
                    if (file_exists($sqlFile)) {
                        exec("mysql -u asterisk -pMaja1234! db_ucx < " . escapeshellarg($sqlFile) . " 2>&1", $dbOut, $dbRc);
                        if ($dbRc === 0) $restored[] = $mod;
                    }
                } elseif ($mod === 'system_config' && is_dir("$tmpDir/modules/system_config")) {
                    exec("cp -r " . escapeshellarg("$tmpDir/modules/system_config") . "/. /etc/smartcms-asterisk/ 2>/dev/null");
                    $restored[] = 'system_config';
                } elseif ($mod === 'uploads' && is_dir("$tmpDir/modules/uploads/avatars")) {
                    if (!is_dir('/opt/smartcms/backend/storage/avatars')) {
                        mkdir('/opt/smartcms/backend/storage/avatars', 0775, true);
                    }
                    exec("cp -r " . escapeshellarg("$tmpDir/modules/uploads/avatars") . "/. /opt/smartcms/backend/storage/avatars/ 2>/dev/null");
                    $restored[] = 'uploads';
                }
            }
            if (in_array('system_config', $restored)) {
                exec("docker exec asterisk asterisk -rx 'core reload' 2>/dev/null");
            }
        } else {
            // ---- v1.0 backward compat restore ----
            $components = $input['components'] ?? $input['modules'] ?? ['database', 'asterisk_config', 'uploads'];
            $includes   = array_values(array_intersect($backupInfo['includes'] ?? [], $components));

            if (in_array('database', $includes) && file_exists("$tmpDir/database.sql")) {
                exec("mysql -u asterisk -pMaja1234! db_ucx < " . escapeshellarg("$tmpDir/database.sql") . " 2>&1", $dbOut, $dbRc);
                if ($dbRc === 0) $restored[] = 'database';
            }
            if (in_array('asterisk_config', $includes) && is_dir("$tmpDir/asterisk-config")) {
                exec("cp -r " . escapeshellarg("$tmpDir/asterisk-config") . "/. /etc/smartcms-asterisk/ 2>/dev/null");
                exec("docker exec asterisk asterisk -rx 'core reload' 2>/dev/null");
                $restored[] = 'system_config';
            }
            if (in_array('uploads', $includes) && is_dir("$tmpDir/uploads/avatars")) {
                if (!is_dir('/opt/smartcms/backend/storage/avatars')) {
                    mkdir('/opt/smartcms/backend/storage/avatars', 0775, true);
                }
                exec("cp -r " . escapeshellarg("$tmpDir/uploads/avatars") . "/. /opt/smartcms/backend/storage/avatars/ 2>/dev/null");
                $restored[] = 'uploads';
            }
        }

        exec("rm -rf " . escapeshellarg($tmpDir));

        try {
            $pdo->prepare("INSERT INTO activity_logs (user_id, action, entity_type, ip_address, user_agent, new_values, created_at) VALUES (?, 'restored', 'backup', ?, ?, ?, NOW())")
                ->execute([$bkUser['id'], $_SERVER['REMOTE_ADDR'] ?? 'unknown', substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255), json_encode(['modules' => $restored])]);
        } catch (Exception $e) {}

        echo json_encode(['success' => true, 'restored' => $restored, 'backup_info' => $backupInfo]);
        exit;
    }

    http_response_code(404);
    echo json_encode(['error' => 'Unknown backup action: ' . $action]);
    exit;
}

// ============================================================
// CMS POLICIES API  (role-hierarchy aware)
// ============================================================
if ($resource === 'cms-policies') {
    // Auth
    $cpHeaders = getallheaders();
    $cpAuthH   = $cpHeaders['Authorization'] ?? $cpHeaders['authorization'] ?? $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    $cpUser    = null;
    if (preg_match('/Bearer\s+(.+)/i', $cpAuthH, $cpTok)) {
        $cpStmt = $pdo->prepare(
            "SELECT u.id, u.name, u.role, COALESCE(cp.level, 99) AS my_level
             FROM users u
             LEFT JOIN cms_policies cp ON u.policy_id = cp.id
             WHERE u.remember_token = ? AND u.is_active = 1"
        );
        $cpStmt->execute([trim($cpTok[1])]);
        $cpUser = $cpStmt->fetch(PDO::FETCH_ASSOC);
    }
    if (!$cpUser) {
        http_response_code(401); echo json_encode(['error' => 'Unauthorized']); exit;
    }
    if (!in_array($cpUser['role'], ['super_admin', 'admin', 'operator'])) {
        http_response_code(403); echo json_encode(['error' => 'Forbidden']); exit;
    }
    $myLevel = (int)$cpUser['my_level'];

    // All permission columns
    $permCols = [
        'can_view_secret_extension','can_edit_secret_extension','can_edit_name_extension',
        'can_view_secret_3rdparty','can_edit_secret_3rdparty','can_edit_name_3rdparty',
        'can_create_extension','can_delete_extension',
        'can_create_line','can_delete_line',
        'can_create_vpw','can_delete_vpw',
        'can_create_cas','can_delete_cas',
        'can_create_3rdparty','can_delete_3rdparty',
        'can_manage_trunks','can_manage_sbc','can_manage_call_servers',
    ];

    // ---- GET /v1/cms-policies  (list) ----
    if ($method === 'GET' && !$id) {
        $stmt = $pdo->prepare(
            "SELECT id, name, role, description, level, " . implode(',', $permCols) . ", is_active, created_at, updated_at
             FROM cms_policies WHERE level >= ? ORDER BY level ASC, id ASC"
        );
        $stmt->execute([$myLevel]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        // Cast booleans
        foreach ($rows as &$r) {
            foreach ($permCols as $c) { $r[$c] = (bool)$r[$c]; }
            $r['is_active'] = (bool)$r['is_active'];
            $r['level'] = (int)$r['level'];
        }
        echo json_encode(['data' => $rows, 'my_level' => $myLevel]);
        exit;
    }

    // ---- GET /v1/cms-policies/{id} ----
    if ($method === 'GET' && $id) {
        $stmt = $pdo->prepare("SELECT * FROM cms_policies WHERE id = ?");
        $stmt->execute([(int)$id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) { http_response_code(404); echo json_encode(['error' => 'Policy not found']); exit; }
        if ((int)$row['level'] < $myLevel) {
            http_response_code(403); echo json_encode(['error' => 'Forbidden: insufficient privilege level']); exit;
        }
        foreach ($permCols as $c) { $row[$c] = (bool)($row[$c] ?? false); }
        $row['is_active'] = (bool)$row['is_active'];
        $row['level'] = (int)$row['level'];
        echo json_encode(['data' => $row]);
        exit;
    }

    // ---- POST /v1/cms-policies  (create) ----
    if ($method === 'POST' && !$id) {
        if (empty($input['name'])) {
            http_response_code(400); echo json_encode(['error' => 'Policy name is required']); exit;
        }
        $newLevel = isset($input['level']) ? (int)$input['level'] : ($myLevel + 1);
        if ($newLevel <= $myLevel) {
            http_response_code(403);
            echo json_encode(['error' => "Cannot create policy with level $newLevel — must be greater than your level ($myLevel)"]);
            exit;
        }
        // Build INSERT
        $cols   = ['name', 'role', 'description', 'level'];
        $vals   = [
            $input['name'],
            $input['role'] ?? 'operator',
            $input['description'] ?? null,
            $newLevel,
        ];
        foreach ($permCols as $c) {
            $cols[] = $c;
            $vals[] = !empty($input[$c]) ? 1 : 0;
        }
        $cols[] = 'is_active';
        $vals[] = isset($input['is_active']) ? (int)(bool)$input['is_active'] : 1;

        $placeholders = implode(',', array_fill(0, count($cols), '?'));
        $colList      = implode(',', array_map(fn($c) => "`$c`", $cols));
        $pdo->prepare("INSERT INTO cms_policies ($colList) VALUES ($placeholders)")->execute($vals);
        $newId = $pdo->lastInsertId();

        $stmt = $pdo->prepare("SELECT * FROM cms_policies WHERE id = ?");
        $stmt->execute([$newId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        foreach ($permCols as $c) { $row[$c] = (bool)($row[$c] ?? false); }
        $row['is_active'] = (bool)$row['is_active'];
        $row['level'] = (int)$row['level'];
        http_response_code(201);
        echo json_encode(['success' => true, 'data' => $row]);
        exit;
    }

    // ---- PUT /v1/cms-policies/{id}  (update) ----
    if (in_array($method, ['PUT', 'PATCH']) && $id) {
        $targetId = (int)$id;
        $stmt = $pdo->prepare("SELECT * FROM cms_policies WHERE id = ?");
        $stmt->execute([$targetId]);
        $target = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$target) { http_response_code(404); echo json_encode(['error' => 'Policy not found']); exit; }
        // Must be able to manage this level
        if ((int)$target['level'] <= $myLevel) {
            http_response_code(403);
            echo json_encode(['error' => 'Cannot edit policy at or above your privilege level']);
            exit;
        }
        // Cannot escalate level to <= myLevel
        if (isset($input['level']) && (int)$input['level'] <= $myLevel) {
            http_response_code(403);
            echo json_encode(['error' => "Cannot set level to {$input['level']} — must be greater than your level ($myLevel)"]);
            exit;
        }
        // Protected: level of policy id=1 cannot change
        if ($targetId === 1 && isset($input['level']) && (int)$input['level'] !== (int)$target['level']) {
            http_response_code(403);
            echo json_encode(['error' => 'Cannot change the level of the Super Admin Policy']);
            exit;
        }

        $setClauses = [];
        $setVals    = [];
        if (isset($input['name']))        { $setClauses[] = 'name = ?';        $setVals[] = $input['name']; }
        if (isset($input['role']))        { $setClauses[] = 'role = ?';        $setVals[] = $input['role']; }
        if (isset($input['description'])) { $setClauses[] = 'description = ?'; $setVals[] = $input['description']; }
        if (isset($input['level']) && $targetId !== 1) {
            $setClauses[] = 'level = ?'; $setVals[] = (int)$input['level'];
        }
        foreach ($permCols as $c) {
            if (array_key_exists($c, $input)) { $setClauses[] = "$c = ?"; $setVals[] = $input[$c] ? 1 : 0; }
        }
        if (array_key_exists('is_active', $input)) {
            $setClauses[] = 'is_active = ?'; $setVals[] = $input['is_active'] ? 1 : 0;
        }
        if (!empty($setClauses)) {
            $setVals[] = $targetId;
            $pdo->prepare("UPDATE cms_policies SET " . implode(',', $setClauses) . " WHERE id = ?")->execute($setVals);
        }
        $stmt->execute([$targetId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        foreach ($permCols as $c) { $row[$c] = (bool)($row[$c] ?? false); }
        $row['is_active'] = (bool)$row['is_active'];
        $row['level'] = (int)$row['level'];
        echo json_encode(['success' => true, 'data' => $row]);
        exit;
    }

    // ---- DELETE /v1/cms-policies/{id} ----
    if ($method === 'DELETE' && $id) {
        $targetId = (int)$id;
        $stmt = $pdo->prepare("SELECT * FROM cms_policies WHERE id = ?");
        $stmt->execute([$targetId]);
        $target = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$target) { http_response_code(404); echo json_encode(['error' => 'Policy not found']); exit; }
        // Protected policies (Super Admin, Admin defaults)
        if (in_array($targetId, [1, 2])) {
            http_response_code(403);
            echo json_encode(['error' => 'Cannot delete built-in policies']);
            exit;
        }
        // Must be able to manage this level
        if ((int)$target['level'] <= $myLevel) {
            http_response_code(403);
            echo json_encode(['error' => 'Cannot delete policy at or above your privilege level']);
            exit;
        }
        // Check users still using this policy
        $usersStmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE policy_id = ?");
        $usersStmt->execute([$targetId]);
        $userCount = (int)$usersStmt->fetchColumn();
        if ($userCount > 0) {
            http_response_code(409);
            echo json_encode(['error' => "Policy is used by $userCount user(s). Reassign users before deleting."]);
            exit;
        }
        $pdo->prepare("DELETE FROM cms_policies WHERE id = ?")->execute([$targetId]);
        echo json_encode(['success' => true]);
        exit;
    }

    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

// ============================================================
// USERS LIST — hierarchy filter (only show users at >= caller's level)
// ============================================================
if ($resource === 'users' && $method === 'GET' && !$id) {
    // Resolve caller's policy level
    $_uHeaders = function_exists('getallheaders') ? getallheaders() : [];
    $_uAuthH   = $_uHeaders['Authorization'] ?? $_uHeaders['authorization'] ?? $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    $_uLevel   = 99;
    if (preg_match('/Bearer\s+(.+)/i', $_uAuthH, $_uTok)) {
        $_uStmt = $pdo->prepare(
            "SELECT COALESCE(cp.level, 99) AS my_level
             FROM users u LEFT JOIN cms_policies cp ON u.policy_id = cp.id
             WHERE u.remember_token = ? AND u.is_active = 1"
        );
        $_uStmt->execute([trim($_uTok[1])]);
        $_uRow = $_uStmt->fetch(PDO::FETCH_ASSOC);
        if ($_uRow) $_uLevel = (int)$_uRow['my_level'];
    }

    $search  = $_GET['search'] ?? '';
    $page    = max(1, intval($_GET['page'] ?? 1));
    $perPage = max(1, intval($_GET['per_page'] ?? 50));
    $offset  = ($page - 1) * $perPage;

    $where  = "WHERE COALESCE(cp.level, 99) >= ?";
    $params = [$_uLevel];
    if ($search) {
        $where   .= " AND (u.name LIKE ? OR u.email LIKE ?)";
        $params[] = "%$search%";
        $params[] = "%$search%";
    }

    $countStmt = $pdo->prepare(
        "SELECT COUNT(*) FROM users u LEFT JOIN cms_policies cp ON u.policy_id = cp.id $where"
    );
    $countStmt->execute($params);
    $total = (int)$countStmt->fetchColumn();

    $dataStmt = $pdo->prepare(
        "SELECT u.*, cp.name AS policy_name, cp.level AS policy_level
         FROM users u LEFT JOIN cms_policies cp ON u.policy_id = cp.id
         $where ORDER BY u.id DESC LIMIT $perPage OFFSET $offset"
    );
    $dataStmt->execute($params);
    $rows = $dataStmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode([
        'data'         => $rows,
        'current_page' => $page,
        'per_page'     => $perPage,
        'total'        => $total,
        'last_page'    => $perPage > 0 ? (int)ceil($total / $perPage) : 1,
    ]);
    exit;
}

if (!$table) {
    http_response_code(404);
    echo json_encode(['error' => 'Resource not found', 'resource' => $resource]);
    exit;
}

// Resolve current logged-in user from Bearer token (for activity logging)
$currentUserId = null;
try {
    $_allH = function_exists('getallheaders') ? getallheaders() : [];
    $_authH = $_allH['Authorization'] ?? $_allH['authorization'] ?? $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (preg_match('/Bearer\s+(.+)/i', $_authH, $_mTok)) {
        $_us = $pdo->prepare("SELECT id FROM users WHERE remember_token = ?");
        $_us->execute([trim($_mTok[1])]);
        $currentUserId = $_us->fetchColumn() ?: null;
    }
} catch (Exception $_e) {}

try {
    switch ($method) {
        case 'GET':
            if ($id) {
                // Get single record
                $stmt = $pdo->prepare("SELECT * FROM `$table` WHERE id = ?");
                $stmt->execute([$id]);
                $data = $stmt->fetch(PDO::FETCH_ASSOC);

                if (!$data) {
                    http_response_code(404);
                    echo json_encode(['error' => 'Record not found']);
                    exit;
                }

                // Load relations for specific resources
                if ($table === 'customers') {
                    $stmt2 = $pdo->prepare("SELECT COUNT(*) as count FROM head_offices WHERE customer_id = ?");
                    $stmt2->execute([$id]);
                    $data['head_offices_count'] = $stmt2->fetch()['count'];

                    $stmt3 = $pdo->prepare("SELECT COUNT(*) as count FROM branches WHERE customer_id = ?");
                    $stmt3->execute([$id]);
                    $data['branches_count'] = $stmt3->fetch()['count'];
                    $stmt3 = $pdo->prepare("SELECT COUNT(*) as count FROM branches WHERE customer_id = ?");
                    $stmt3->execute([$id]);
                    $data['branches_count'] = $stmt3->fetch()['count'];
                }
                // branches: load customer, head_office, call_server
                if ($table === 'branches') {
                    if (!empty($data['customer_id'])) { $r=$pdo->prepare("SELECT id,name FROM customers WHERE id=?"); $r->execute([$data['customer_id']]); $data['customer']=$r->fetch(PDO::FETCH_ASSOC)?:null; } else { $data['customer']=null; }
                    if (!empty($data['head_office_id'])) { $r=$pdo->prepare("SELECT id,name FROM head_offices WHERE id=?"); $r->execute([$data['head_office_id']]); $data['head_office']=$r->fetch(PDO::FETCH_ASSOC)?:null; } else { $data['head_office']=null; }
                    if (!empty($data['call_server_id'])) { $r=$pdo->prepare("SELECT id,name,host FROM call_servers WHERE id=?"); $r->execute([$data['call_server_id']]); $data['call_server']=$r->fetch(PDO::FETCH_ASSOC)?:null; } else { $data['call_server']=null; }
                }

                // Load IVR entries
                if ($table === 'ivr') {
                    $stmtEntries = $pdo->prepare("SELECT * FROM ivr_entries WHERE ivr_id = ? ORDER BY id ASC");
                    $stmtEntries->execute([$id]);
                    $data['entries'] = $stmtEntries->fetchAll(PDO::FETCH_ASSOC);

                    // Load relations
                    if ($data['announcement']) {
                        $stmtAnn = $pdo->prepare("SELECT id, name FROM announcements WHERE id = ?");
                        $stmtAnn->execute([$data['announcement']]);
                        $data['announcement_data'] = $stmtAnn->fetch(PDO::FETCH_ASSOC);
                    }
                }

                // Load outbound dial patterns
                if ($table === 'outbound_routings') {
                    $stmtPatterns = $pdo->prepare("SELECT * FROM outbound_dial_patterns WHERE outbound_routing_id = ? ORDER BY id ASC");
                    $stmtPatterns->execute([$id]);
                    $data['dial_patterns'] = $stmtPatterns->fetchAll(PDO::FETCH_ASSOC);
                }

                echo json_encode(['data' => $data]);
            } else {
                // Get all records with counts
                $search = $_GET['search'] ?? '';
                $page = intval($_GET['page'] ?? 1);
                $perPage = intval($_GET['per_page'] ?? 50);
                $offset = ($page - 1) * $perPage;

                $where = '';
                $params = [];

                if ($search) {
                    $where = "WHERE name LIKE ?";
                    $params[] = "%$search%";
                }

                // Filter by user_id for activity_logs
                if ($table === 'activity_logs' && isset($_GET['user_id'])) {
                    $op = $where ? " AND " : " WHERE ";
                    $where .= "$op user_id = ?";
                    $params[] = $_GET['user_id'];
                }

                // Type filtering for call_servers: default excludes SBC; ?type=sbc returns SBC only; ?type=all returns all
                if ($table === 'call_servers') {
                    $typeParam = isset($_GET['type']) ? $_GET['type'] : '';
                    if ($typeParam === '') {
                        // Default: exclude SBC type
                        $op = $where ? " AND " : " WHERE ";
                        $where .= "$op (type IS NULL OR type = '' OR type != 'sbc')";
                    } elseif ($typeParam !== 'all') {
                        // Specific type filter (e.g. type=sbc)
                        $op = $where ? " AND " : " WHERE ";
                        $where .= "$op type = ?";
                        $params[] = $typeParam;
                    }
                    // type=all: no filter
                } elseif (isset($_GET['type'])) {
                    // Generic type filtering for other tables with a type column
                    $checkCol = $pdo->query("SHOW COLUMNS FROM `$table` LIKE 'type'")->fetch();
                    if ($checkCol) {
                        $op = $where ? " AND " : " WHERE ";
                        $where .= "$op `type` = ?";
                        $params[] = $_GET['type'];
                    }
                }
                // Count total
                if ($table === 'activity_logs') {
                    $countStmt = $pdo->prepare("SELECT COUNT(*) FROM `activity_logs` al $where");
                } else {
                    $countStmt = $pdo->prepare("SELECT COUNT(*) FROM `$table` $where");
                }
                $countStmt->execute($params);
                $total = $countStmt->fetchColumn();

                // Get data
                if ($table === 'activity_logs') {
                    $sql = "SELECT al.*, u.id AS u_id, u.name AS u_name, u.email AS u_email FROM `activity_logs` al LEFT JOIN users u ON al.user_id = u.id $where ORDER BY al.id DESC LIMIT $perPage OFFSET $offset";
                } else {
                    $sql = "SELECT * FROM `$table` $where ORDER BY id DESC LIMIT $perPage OFFSET $offset";
                }
                $stmt = $pdo->prepare($sql);
                $stmt->execute($params);
                $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

                // Build nested user object for activity_logs
                if ($table === 'activity_logs') {
                    foreach ($rows as &$row) {
                        if (!empty($row['u_id'])) {
                            $row['user'] = [
                                'id'    => $row['u_id'],
                                'name'  => $row['u_name'],
                                'email' => $row['u_email'],
                            ];
                        } else {
                            $row['user'] = null;
                        }
                        unset($row['u_id'], $row['u_name'], $row['u_email']);
                    }
                    unset($row);
                }

                // Add counts for customers
                if ($table === 'customers') {
                    foreach ($rows as &$row) {
                        $stmt2 = $pdo->prepare("SELECT COUNT(*) FROM head_offices WHERE customer_id = ?");
                        $stmt2->execute([$row['id']]);
                        $row['head_offices_count'] = $stmt2->fetchColumn();

                        $stmt3 = $pdo->prepare("SELECT COUNT(*) FROM branches WHERE customer_id = ?");
                        $stmt3->execute([$row['id']]);
                        $row['branches_count'] = $stmt3->fetchColumn();
                    }
                }

                // Add is_active for sbcs (disabled=0 means active)
                if ($table === 'sbcs') {
                    foreach ($rows as &$row) {
                        $row['is_active'] = empty($row['disabled']) ? 1 : 0;
                    }
                    unset($row);
                }

                // Add head_office relation for call_servers
                if ($table === 'call_servers') {
                    foreach ($rows as &$row) {
                        if ($row['head_office_id']) {
                            $stmt2 = $pdo->prepare("SELECT id, name FROM head_offices WHERE id = ?");
                            $stmt2->execute([$row['head_office_id']]);
                            $row['head_office'] = $stmt2->fetch(PDO::FETCH_ASSOC);
                        }
                        // Count extensions, trunks for this call server
                        $stmt3 = $pdo->prepare("SELECT COUNT(*) FROM extensions WHERE call_server_id = ?");
                        $stmt3->execute([$row['id']]);
                        $row['ext_count'] = $stmt3->fetchColumn();

                        $stmt4 = $pdo->prepare("SELECT COUNT(*) FROM trunks WHERE call_server_id = ?");
                        $stmt4->execute([$row['id']]);
                        $row['trunks_count'] = $stmt4->fetchColumn();

                        $row['lines_count'] = 0; // Placeholder
                    }
                }

                // Add customer relation for head_offices
                if ($table === 'head_offices') {
                    // Filter by customer_id if provided
                    $customerId = $_GET['customer_id'] ?? null;
                    if ($customerId) {
                        $rows = array_filter($rows, function ($row) use ($customerId) {
                            return $row['customer_id'] == $customerId;
                        });
                        $rows = array_values($rows);
                    }

                    foreach ($rows as &$row) {
                        if ($row['customer_id']) {
                            $stmt2 = $pdo->prepare("SELECT id, name FROM customers WHERE id = ?");
                            $stmt2->execute([$row['customer_id']]);
                            $row['customer'] = $stmt2->fetch(PDO::FETCH_ASSOC);
                        }
                        $stmt3 = $pdo->prepare("SELECT COUNT(*) FROM branches WHERE head_office_id = ?");
                        $stmt3->execute([$row['id']]);
                        $row['branches_count'] = $stmt3->fetchColumn();

                        $stmt4 = $pdo->prepare("SELECT COUNT(*) FROM call_servers WHERE head_office_id = ?");
                        $stmt4->execute([$row['id']]);
                        $row['call_servers_count'] = $stmt4->fetchColumn();
                    }
                }

                // branches: load customer, head_office, call_server
                if ($table === 'branches') {
                    foreach ($rows as &$row) {
                        if (!empty($row['customer_id'])) { $r=$pdo->prepare("SELECT id,name FROM customers WHERE id=?"); $r->execute([$row['customer_id']]); $row['customer']=$r->fetch(PDO::FETCH_ASSOC)?:null; } else { $row['customer']=null; }
                        if (!empty($row['head_office_id'])) { $r=$pdo->prepare("SELECT id,name FROM head_offices WHERE id=?"); $r->execute([$row['head_office_id']]); $row['head_office']=$r->fetch(PDO::FETCH_ASSOC)?:null; } else { $row['head_office']=null; }
                        if (!empty($row['call_server_id'])) { $r=$pdo->prepare("SELECT id,name,host FROM call_servers WHERE id=?"); $r->execute([$row['call_server_id']]); $row['call_server']=$r->fetch(PDO::FETCH_ASSOC)?:null; } else { $row['call_server']=null; }
                    }
                }

                // Add call_server relation for extensions, vpws, cas, sbcs, trunks, private_wires, device_3rd_parties, inbound_routings, outbound_routings, intercoms, lines
                $csAffectedTables = ['lines', 'extensions', 'vpws', 'cas', 'sbcs', 'trunks', 'private_wires', 'device_3rd_parties', 'inbound_routings', 'outbound_routings', 'intercoms'];
                if (in_array($table, $csAffectedTables)) {
                    foreach ($rows as &$row) {
                        if (isset($row['call_server_id']) && $row['call_server_id']) {
                            $stmt2 = $pdo->prepare("SELECT id, name FROM call_servers WHERE id = ?");
                            $stmt2->execute([$row['call_server_id']]);
                            $row['call_server'] = $stmt2->fetch(PDO::FETCH_ASSOC);
                        }
                    }
                }

                // Extra relations for intercoms
                if ($table === 'intercoms') {
                    foreach ($rows as &$row) {
                        if (isset($row['branch_id']) && $row['branch_id']) {
                            $stmt2 = $pdo->prepare("SELECT id, name FROM branches WHERE id = ?");
                            $stmt2->execute([$row['branch_id']]);
                            $row['branch'] = $stmt2->fetch(PDO::FETCH_ASSOC);
                        }
                    }
                }

                // Extra relations for outbound_routings (trunk)
                if ($table === 'outbound_routings') {
                    foreach ($rows as &$row) {
                        if (isset($row['trunk_id']) && $row['trunk_id']) {
                            $stmt2 = $pdo->prepare("SELECT id, name FROM trunks WHERE id = ?");
                            $stmt2->execute([$row['trunk_id']]);
                            $row['trunk'] = $stmt2->fetch(PDO::FETCH_ASSOC);
                        }
                    }
                }

                // Add relations for sbc_routes (SBC, trunk)
                // Add relations for sbc_routes (SBC Node, Connection Leg)
                if ($table === 'sbc_routes') {
                    foreach ($rows as &$row) {
                        // Source relations
                        if (isset($row['src_call_server_id']) && $row['src_call_server_id']) {
                            $stmt2 = $pdo->prepare("SELECT id, name FROM call_servers WHERE id = ?");
                            $stmt2->execute([$row['src_call_server_id']]);
                            $row['src_call_server'] = $stmt2->fetch(PDO::FETCH_ASSOC);
                        }
                        if (isset($row['src_from_sbc_id']) && $row['src_from_sbc_id']) {
                            $stmt2 = $pdo->prepare("SELECT id, name FROM sbcs WHERE id = ?");
                            $stmt2->execute([$row['src_from_sbc_id']]);
                            $row['src_from_sbc'] = $stmt2->fetch(PDO::FETCH_ASSOC);
                        }
                        // Destination relations
                        if (isset($row['dest_call_server_id']) && $row['dest_call_server_id']) {
                            $stmt2 = $pdo->prepare("SELECT id, name FROM call_servers WHERE id = ?");
                            $stmt2->execute([$row['dest_call_server_id']]);
                            $row['dest_call_server'] = $stmt2->fetch(PDO::FETCH_ASSOC);
                        }
                        if (isset($row['dest_from_sbc_id']) && $row['dest_from_sbc_id']) {
                            $stmt2 = $pdo->prepare("SELECT id, name FROM sbcs WHERE id = ?");
                            $stmt2->execute([$row['dest_from_sbc_id']]);
                            $row['dest_from_sbc'] = $stmt2->fetch(PDO::FETCH_ASSOC);
                        }
                    }
                }

                // Add relation for turret_groups (include members)
                if ($table === 'turret_groups') {
                    foreach ($rows as &$row) {
                        $stmt2 = $pdo->prepare("SELECT extension FROM turret_group_members WHERE group_id = ?");
                        $stmt2->execute([$row['id']]);
                        $members = $stmt2->fetchAll(PDO::FETCH_COLUMN);
                        $row['members'] = $members; // Return as simple array of extensions
                    }
                }

                echo json_encode([
                    'data' => $rows,
                    'current_page' => $page,
                    'per_page' => $perPage,
                    'total' => $total,
                    'last_page' => ceil($total / $perPage)
                ]);
            }
            break;

        case 'POST':
        case 'PUT':
            if ($method === 'PUT' && !$id) {
                http_response_code(400);
                echo json_encode(['error' => 'ID required']);
                exit;
            }

            // Hash password for users table
            if ($table === 'users' && isset($input['password']) && !empty($input['password'])) {
                $input['password'] = password_hash($input['password'], PASSWORD_BCRYPT);
            }

            // Handle Profile Image Upload
            if ($table === 'users' && isset($input['profile_image']) && !empty($input['profile_image'])) {
                if (preg_match('/^data:image\/([a-zA-Z0-9+.-]+);base64,/', $input['profile_image'], $type)) {
                    $imageData = substr($input['profile_image'], strpos($input['profile_image'], ',') + 1);
                    $decoded = base64_decode($imageData);

                    if ($decoded !== false) {
                        $extension = strtolower($type[1]);
                        if ($extension === 'svg+xml')
                            $extension = 'svg';
                        if ($extension === 'jpeg')
                            $extension = 'jpg';

                        if (in_array($extension, ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg'])) {
                            $filename = 'user_' . time() . '_' . uniqid() . '.' . $extension;
                            $uploadDir = is_dir('src/assets') ? 'src/assets/images/user-profiles/' : 'assets/images/user-profiles/';
                            if (!file_exists($uploadDir))
                                mkdir($uploadDir, 0777, true);
                            if (file_put_contents($uploadDir . $filename, $decoded)) {
                                $input['profile_image'] = $filename;
                            } else {
                                unset($input['profile_image']);
                            }
                        } else {
                            unset($input['profile_image']);
                        }
                    }
                }
                if (isset($input['profile_image']) && strlen($input['profile_image']) > 255) {
                    unset($input['profile_image']);
                }
            }

            // Convert booleans for MariaDB
            foreach ($input as $key => &$val) {
                if (is_bool($val))
                    $val = $val ? 1 : 0;
            }

            try {
                // AUTO MIGRATION & Schema Check
                $schemaStmt = $pdo->query("DESCRIBE `$table`");
                $allowedColumns = $schemaStmt->fetchAll(PDO::FETCH_COLUMN);

                if (empty($allowedColumns))
                    throw new Exception("Table `$table` schema empty.");

                $missingColumns = array_diff(array_keys($input), $allowedColumns);
                if (!empty($missingColumns)) {
                    foreach ($missingColumns as $col) {
                        if (in_array(strtolower($col), ['id', 'created_at', 'updated_at', 'deleted_at']))
                            continue;
                        $sqlType = "TEXT NULL";
                        if (strpos($col, 'is_') === 0 || strpos($col, 'has_') === 0 || $col === 'disabled' || $col === 'active')
                            $sqlType = "TINYINT(1) DEFAULT 0";
                        if (strpos($col, 'port') !== false || strpos($col, '_id') !== false)
                            $sqlType = "INT NULL";
                        if ($col === 'secret' || $col === 'password')
                            $sqlType = "VARCHAR(255) NULL";

                        $pdo->exec("ALTER TABLE `$table` ADD COLUMN `$col` $sqlType");
                    }
                    $schemaStmt = $pdo->query("DESCRIBE `$table`");
                    $allowedColumns = $schemaStmt->fetchAll(PDO::FETCH_COLUMN);
                }

                $filteredInput = array_intersect_key($input, array_flip($allowedColumns));

                // Prevent arrays like 'entries' from being saved to main table (they are handled separately)
                if (isset($filteredInput['entries']))
                    unset($filteredInput['entries']);
                if (isset($filteredInput['members']) && $table === 'turret_groups')
                    unset($filteredInput['members']);
                if (isset($filteredInput['dial_patterns']))
                    unset($filteredInput['dial_patterns']);

                // Fetch old data before update (for old_values in activity log)
                $oldData = null;
                if ($method !== 'POST' && $id) {
                    try {
                        $_os = $pdo->prepare("SELECT * FROM `$table` WHERE id = ?");
                        $_os->execute([$id]);
                        $oldData = $_os->fetch(PDO::FETCH_ASSOC) ?: null;
                    } catch (Exception $_e) {}
                }

                if ($method === 'POST') {
                    $columns = array_keys($filteredInput);
                    $placeholders = array_fill(0, count($columns), '?');
                    $sql = "INSERT INTO `$table` (`" . implode("`,`", $columns) . "`) VALUES (" . implode(',', $placeholders) . ")";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute(array_values($filteredInput));
                    $dataId = $pdo->lastInsertId();
                    // Log created activity
                    if (!in_array($table, ['activity_logs', 'system_logs', 'call_logs'])) {
                        try {
                            $_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                            $_ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);
                            $__l = $pdo->prepare("INSERT INTO `activity_logs` (user_id, action, entity_type, entity_id, ip_address, user_agent, new_values) VALUES (?, 'created', ?, ?, ?, ?, ?)");
                            $__l->execute([$currentUserId, $table, $dataId, $_ip, $_ua, json_encode($filteredInput)]);
                        } catch (Exception $_e) {}
                    }
                } else {
                    $sets = [];
                    $values = [];
                    foreach ($filteredInput as $key => $value) {
                        $sets[] = "`$key` = ?";
                        $values[] = $value;
                    }
                    $values[] = $id;
                    $sql = "UPDATE `$table` SET " . implode(', ', $sets) . " WHERE id = ?";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute($values);
                    $dataId = $id;
                    // Log updated activity (all tables)
                    if (!in_array($table, ['activity_logs', 'system_logs', 'call_logs'])) {
                        try {
                            $_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                            $_ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);
                            $__l = $pdo->prepare("INSERT INTO `activity_logs` (user_id, action, entity_type, entity_id, ip_address, user_agent, old_values, new_values) VALUES (?, 'updated', ?, ?, ?, ?, ?, ?)");
                            $__l->execute([$currentUserId, $table, $id, $_ip, $_ua, $oldData ? json_encode($oldData) : null, json_encode($filteredInput)]);
                        } catch (Exception $_e) {}
                    }
                }

                // Sync Turret Group Members
                if ($table === 'turret_groups' && isset($input['members']) && is_array($input['members'])) {
                    $pdo->prepare("DELETE FROM turret_group_members WHERE group_id = ?")->execute([$dataId]);
                    $stmtLink = $pdo->prepare("INSERT INTO turret_group_members (group_id, extension) VALUES (?, ?)");
                    foreach ($input['members'] as $ext) {
                        $stmtLink->execute([$dataId, $ext]);
                    }
                }

                // Handle IVR Entries Saving
                if ($table === 'ivr' && isset($input['entries']) && is_array($input['entries'])) {
                    // Delete existing entries
                    $pdo->prepare("DELETE FROM ivr_entries WHERE ivr_id = ?")->execute([$dataId]);

                    // Insert new entries
                    $stmtEntry = $pdo->prepare("INSERT INTO ivr_entries (ivr_id, digits, destination, return_to_ivr) VALUES (?, ?, ?, ?)");
                    foreach ($input['entries'] as $entry) {
                        $stmtEntry->execute([
                            $dataId,
                            $entry['digits'] ?? '',
                            $entry['destination'] ?? null,
                            isset($entry['return_to_ivr']) && $entry['return_to_ivr'] ? 1 : 0
                        ]);
                    }
                }

                // Handle Outbound Dial Patterns Saving
                if ($table === 'outbound_routings' && isset($input['dial_patterns']) && is_array($input['dial_patterns'])) {
                    // Delete existing patterns
                    $pdo->prepare("DELETE FROM outbound_dial_patterns WHERE outbound_routing_id = ?")->execute([$dataId]);

                    // Insert new patterns
                    $stmtPattern = $pdo->prepare("INSERT INTO outbound_dial_patterns (outbound_routing_id, prepend, prefix, match_pattern, caller_id) VALUES (?, ?, ?, ?, ?)");
                    foreach ($input['dial_patterns'] as $pattern) {
                        $stmtPattern->execute([
                            $dataId,
                            $pattern['prepend'] ?? null,
                            $pattern['prefix'] ?? null,
                            $pattern['match_pattern'] ?? null,
                            $pattern['caller_id'] ?? null
                        ]);
                    }
                }

                $stmt2 = $pdo->prepare("SELECT * FROM `$table` WHERE id = ?");
                $stmt2->execute([$dataId]);
                $finalData = $stmt2->fetch(PDO::FETCH_ASSOC);

                http_response_code($method === 'POST' ? 201 : 200);
                echo json_encode(['message' => ($method === 'POST' ? 'Created' : 'Updated') . ' successfully', 'data' => $finalData]);
            } catch (Exception $e) {
                http_response_code(500);
                echo json_encode(['error' => 'Database error: ' . $e->getMessage(), 'sql' => $sql ?? 'N/A']);
            }
            break;

        case 'DELETE':
            if (!$id) {
                http_response_code(400);
                echo json_encode(['error' => 'ID required']);
                exit;
            }
            // Block deletion of activity logs
            if ($table === 'activity_logs') {
                http_response_code(405);
                echo json_encode(['error' => 'Deleting activity logs is not allowed']);
                exit;
            }

            $stmt = $pdo->prepare("DELETE FROM `$table` WHERE id = ?");
            $stmt->execute([$id]);
            // Log deleted activity
            if (!in_array($table, ['activity_logs', 'system_logs', 'call_logs'])) {
                try {
                    $_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                    $_ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);
                    $__l = $pdo->prepare("INSERT INTO `activity_logs` (user_id, action, entity_type, entity_id, ip_address, user_agent) VALUES (?, 'deleted', ?, ?, ?, ?)");
                    $__l->execute([$currentUserId, $table, $id, $_ip, $_ua]);
                } catch (Exception $_e) {}
            }

            echo json_encode(['message' => 'Deleted successfully']);
            break;

        default:
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
    }
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
}

// Helper function to get simple dropdown lists
if ($resource === 'dropdowns' && $method === 'GET') {
    $type = $_GET['type'] ?? '';
    if ($type === 'announcements') {
        $stmt = $pdo->query("SELECT id, name FROM announcements ORDER BY name");
        echo json_encode(['data' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
        exit;
    }
    if ($type === 'recordings') {
        $stmt = $pdo->query("SELECT id, name FROM recordings ORDER BY name");
        echo json_encode(['data' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
        exit;
    }
}
