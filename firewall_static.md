# Firewall & Static Route - Device Integration

## Summary

Firewall dan Static Route adalah konfigurasi **OS-level** yang perlu di-push ke device fisik (Call Server, SBC, Recording Server). CMS berfungsi sebagai central management untuk menyimpan config dan nantinya push ke target device.

---

## Yang Sudah Diimplementasi

### Database Tables

```sql
-- Static Routes
CREATE TABLE static_routes (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    destination VARCHAR(50) NOT NULL,      -- CIDR: 192.168.1.0/24
    gateway VARCHAR(50) NOT NULL,           -- Gateway IP
    interface_name VARCHAR(20) DEFAULT 'eth0',
    metric INT DEFAULT 100,
    device_type ENUM('call_server', 'sbc', 'recording') NOT NULL,
    device_id BIGINT UNSIGNED NOT NULL,
    is_active TINYINT(1) DEFAULT 1,
    ...
);

-- Firewall Rules
CREATE TABLE firewall_rules (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    protocol ENUM('TCP', 'UDP', 'ICMP', 'ALL'),
    port VARCHAR(50) NOT NULL,              -- Port or range: 5060, 10000-20000
    source VARCHAR(50) DEFAULT 'Any',
    action ENUM('ACCEPT', 'DROP', 'REJECT'),
    priority INT DEFAULT 100,
    device_type ENUM('call_server', 'sbc', 'recording') NOT NULL,
    device_id BIGINT UNSIGNED NOT NULL,
    is_active TINYINT(1) DEFAULT 1,
    ...
);
```

### Frontend Features
- ✅ Device Type dropdown (Call Server / SBC / Recording)
- ✅ Device dropdown (cascading, berisi list device sesuai type)
- ✅ Kolom Device di tabel list
- ✅ Data tersimpan ke database

---

## Rencana: Push Config ke Device via SSH/API

### Arsitektur

```
┌─────────────┐     Save      ┌─────────────┐     Apply      ┌─────────────┐
│   CMS UI    │ ───────────►  │   Database  │ ────────────►  │   Device    │
│  (Angular)  │               │  (MariaDB)  │    SSH/API     │(Call Server)│
└─────────────┘               └─────────────┘                └─────────────┘
```

### Flow Detail

1. **User** buat config di CMS (Firewall Rule / Static Route)
2. **CMS** simpan ke database dengan `device_type` + `device_id`
3. **User** klik tombol **"Apply"** / **"Push to Device"**
4. **Backend** lookup device credentials dari `call_servers` table
5. **Backend** SSH ke device atau call REST API
6. **Backend** execute command:
   - Static Route: `ip route add {destination} via {gateway} dev {interface}`
   - Firewall: `iptables -A INPUT -p {protocol} --dport {port} -s {source} -j {action}`

### Yang Dibutuhkan

| Item | Keterangan |
|------|------------|
| SSH Credentials | Tambah field `ssh_user`, `ssh_password`/`ssh_key` di `call_servers` |
| PHP SSH Library | `phpseclib` atau native `ssh2_connect()` |
| API Endpoint | `POST /v1/static-routes/{id}/apply` |
| Device API (optional) | Jika device support REST API, bisa pakai HTTP call |

### Contoh Backend Code (PHP)

```php
// POST /v1/static-routes/{id}/apply
function applyStaticRoute($routeId) {
    // 1. Get route from DB
    $route = getRouteById($routeId);
    
    // 2. Get device credentials
    $device = getDeviceCredentials($route['device_type'], $route['device_id']);
    
    // 3. SSH to device
    $ssh = new SSH2($device['ip_address']);
    $ssh->login($device['ssh_user'], $device['ssh_password']);
    
    // 4. Execute command
    $cmd = "ip route add {$route['destination']} via {$route['gateway']} dev {$route['interface_name']}";
    $result = $ssh->exec($cmd);
    
    return ['success' => true, 'output' => $result];
}
```

### UI Enhancement (Future)

- Tombol **"Apply"** di setiap row tabel
- Status indicator: **Synced** / **Pending** / **Failed**
- Bulk apply: "Apply All to Device X"

---

## Files Modified

| File | Perubahan |
|------|-----------|
| `api.php` | Tambah endpoint `static-routes`, `firewall-rules` |
| `static-route.ts` | Connect ke DB, device selector |
| `static-route.html` | Device dropdown, kolom Device |
| `firewall.ts` | Connect ke DB, device selector |
| `firewall.html` | Device dropdown, kolom Device |

---

## Next Steps

1. [ ] Tambah SSH credentials ke `call_servers` table
2. [ ] Install PHP SSH library (`phpseclib`)
3. [ ] Buat endpoint `/apply` untuk push config
4. [ ] Tambah tombol "Apply" di UI
5. [ ] Tambah status sync indicator
