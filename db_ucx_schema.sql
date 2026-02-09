-- =====================================================
-- Database: db_ucx
-- Schema for Smart UCX CMS
-- Created: 2026-01-30
-- =====================================================

-- =====================================================
-- 1. ORGANIZATION MODULE
-- =====================================================

-- Customers (Companies)
CREATE TABLE IF NOT EXISTS customers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    code VARCHAR(50),
    contact_person VARCHAR(255),
    email VARCHAR(255),
    phone VARCHAR(50),
    address TEXT,
    is_active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Head Offices
CREATE TABLE IF NOT EXISTS head_offices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    customer_id INT,
    name VARCHAR(255) NOT NULL,
    code VARCHAR(50),
    type ENUM('basic', 'ha', 'fo') DEFAULT 'basic',
    country VARCHAR(100),
    province VARCHAR(100),
    city VARCHAR(100),
    district VARCHAR(100),
    address TEXT,
    contact_name VARCHAR(255),
    contact_phone VARCHAR(50),
    description TEXT,
    is_active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Branches
CREATE TABLE IF NOT EXISTS branches (
    id INT AUTO_INCREMENT PRIMARY KEY,
    customer_id INT,
    head_office_id INT,
    call_server_id INT,
    name VARCHAR(255) NOT NULL,
    code VARCHAR(50),
    country VARCHAR(100),
    province VARCHAR(100),
    city VARCHAR(100),
    district VARCHAR(100),
    address TEXT,
    contact_name VARCHAR(255),
    contact_phone VARCHAR(50),
    description TEXT,
    is_active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE SET NULL,
    FOREIGN KEY (head_office_id) REFERENCES head_offices(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Sub Branches
CREATE TABLE IF NOT EXISTS sub_branches (
    id INT AUTO_INCREMENT PRIMARY KEY,
    customer_id INT,
    branch_id INT,
    name VARCHAR(255) NOT NULL,
    code VARCHAR(50),
    country VARCHAR(100),
    province VARCHAR(100),
    city VARCHAR(100),
    district VARCHAR(100),
    address TEXT,
    contact_name VARCHAR(255),
    contact_phone VARCHAR(50),
    description TEXT,
    is_active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE SET NULL,
    FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- 2. CONNECTIVITY MODULE
-- =====================================================

-- Call Servers
CREATE TABLE IF NOT EXISTS call_servers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    head_office_id INT,
    type VARCHAR(20) DEFAULT 'pbx',
    name VARCHAR(255) NOT NULL,
    host VARCHAR(255) NOT NULL,
    port INT DEFAULT 5060,
    description TEXT,
    is_active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (head_office_id) REFERENCES head_offices(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Extensions (Users/Lines)
CREATE TABLE IF NOT EXISTS extensions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    call_server_id INT,
    extension VARCHAR(20) NOT NULL,
    name VARCHAR(100),
    password VARCHAR(100),
    voicemail VARCHAR(50),
    outbound_cid VARCHAR(50),
    ring_timer INT DEFAULT 30,
    is_active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (call_server_id) REFERENCES call_servers(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Trunks
CREATE TABLE IF NOT EXISTS trunks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    call_server_id INT,
    name VARCHAR(100) NOT NULL,
    tech VARCHAR(20) DEFAULT 'pjsip',
    host VARCHAR(255),
    port INT DEFAULT 5060,
    username VARCHAR(100),
    secret VARCHAR(100),
    context VARCHAR(100) DEFAULT 'from-trunk',
    outcid VARCHAR(100),
    max_channels INT DEFAULT 0,
    is_disabled TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (call_server_id) REFERENCES call_servers(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Ring Groups
CREATE TABLE IF NOT EXISTS ring_groups (
    id INT AUTO_INCREMENT PRIMARY KEY,
    call_server_id INT,
    grp_num VARCHAR(20) NOT NULL,
    description VARCHAR(100),
    strategy VARCHAR(50) DEFAULT 'ringall',
    grp_time INT DEFAULT 20,
    grp_list TEXT,
    destination VARCHAR(255),
    is_active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (call_server_id) REFERENCES call_servers(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- IVR
CREATE TABLE IF NOT EXISTS ivr (
    id INT AUTO_INCREMENT PRIMARY KEY,
    call_server_id INT,
    name VARCHAR(100) NOT NULL,
    description VARCHAR(255),
    announcement INT,
    direct_dial VARCHAR(50),
    timeout_time INT DEFAULT 10,
    invalid_loops INT DEFAULT 3,
    timeout_destination VARCHAR(255),
    invalid_destination VARCHAR(255),
    is_active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (call_server_id) REFERENCES call_servers(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Time Conditions
CREATE TABLE IF NOT EXISTS time_conditions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    call_server_id INT,
    name VARCHAR(100) NOT NULL,
    description VARCHAR(255),
    time_group_id INT,
    match_destination VARCHAR(255),
    nomatch_destination VARCHAR(255),
    is_active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (call_server_id) REFERENCES call_servers(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Conferences
CREATE TABLE IF NOT EXISTS conferences (
    id INT AUTO_INCREMENT PRIMARY KEY,
    call_server_id INT,
    conf_num VARCHAR(20) NOT NULL,
    name VARCHAR(100),
    pin VARCHAR(20),
    admin_pin VARCHAR(20),
    options VARCHAR(255),
    is_active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (call_server_id) REFERENCES call_servers(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- 3. VOICE GATEWAY MODULE
-- =====================================================

-- DAHDI Channels (Analog/E1)
CREATE TABLE IF NOT EXISTS dahdi_channels (
    id INT AUTO_INCREMENT PRIMARY KEY,
    call_server_id INT,
    channel_type ENUM('fxo', 'fxs', 'e1', 'e1_cas') NOT NULL,
    span INT,
    channel INT,
    signalling VARCHAR(50),
    context VARCHAR(100),
    description VARCHAR(255),
    is_active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (call_server_id) REFERENCES call_servers(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- 4. CMS ADMINISTRATION
-- =====================================================

-- CMS Users
CREATE TABLE IF NOT EXISTS cms_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin', 'operator', 'viewer') DEFAULT 'viewer',
    is_active TINYINT(1) DEFAULT 1,
    last_login TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- CMS Groups
CREATE TABLE IF NOT EXISTS cms_groups (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description VARCHAR(255),
    permissions TEXT,
    is_active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- 5. LOGS
-- =====================================================

-- Activity Logs
CREATE TABLE IF NOT EXISTS activity_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(100),
    entity_id INT,
    old_values TEXT,
    new_values TEXT,
    ip_address VARCHAR(45),
    user_agent VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES cms_users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- System Logs
CREATE TABLE IF NOT EXISTS system_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    level ENUM('debug', 'info', 'warning', 'error', 'critical') DEFAULT 'info',
    message TEXT NOT NULL,
    context TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- 6. SAMPLE DATA
-- =====================================================

-- Insert sample company
INSERT INTO customers (name, code, contact_person, email, phone, address, is_active) VALUES
('PT Smart Infinite Prosperity', 'SIP', 'Joni Me Ow', 'joni@smart.com', '02150877432', 'Jakarta, Indonesia', 1);

-- Insert sample head office
INSERT INTO head_offices (customer_id, name, code, type, city, is_active) VALUES
(1, 'HO Jakarta', 'HO-JKT', 'ha', 'Jakarta', 1);

-- Insert sample call server
INSERT INTO call_servers (head_office_id, name, host, port, is_active) VALUES
(1, 'SmartUCX-1-HO', '103.154.80.172', 5060, 1);

-- Insert sample CMS admin user
INSERT IGNORE INTO cms_users (name, email, password, role, is_active) VALUES
('Administrator', 'admin@smartcms.local', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin', 1);

-- =====================================================
-- 7. SBC MODULE (DYNAMIC)
-- =====================================================

-- SBC Connections
CREATE TABLE IF NOT EXISTS sbcs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    call_server_id INT,
    name VARCHAR(255) NOT NULL,
    sip_server VARCHAR(255),
    sip_server_port INT DEFAULT 5060,
    outcid VARCHAR(255),
    maxchans INT DEFAULT 2,
    transport VARCHAR(20) DEFAULT 'udp',
    context VARCHAR(100) DEFAULT 'from-pstn',
    codecs VARCHAR(255) DEFAULT 'ulaw,alaw',
    dtmfmode VARCHAR(20) DEFAULT 'auto',
    registration VARCHAR(20) DEFAULT 'none',
    auth_username VARCHAR(255),
    secret VARCHAR(255),
    qualify TINYINT(1) DEFAULT 1,
    qualify_frequency INT DEFAULT 60,
    disabled TINYINT(1) DEFAULT 0,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (call_server_id) REFERENCES call_servers(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- SBC Routes
CREATE TABLE IF NOT EXISTS sbc_routes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    src_call_server_id INT,
    src_description VARCHAR(255),
    src_pattern VARCHAR(255),
    src_cid_filter VARCHAR(255),
    src_priority INT DEFAULT 0,
    src_is_active TINYINT(1) DEFAULT 1,
    src_from_sbc_id INT,
    src_destination_id INT,
    dest_call_server_id INT,
    dest_description VARCHAR(255),
    dest_pattern VARCHAR(255),
    dest_cid_filter VARCHAR(255),
    dest_priority INT DEFAULT 0,
    dest_is_active TINYINT(1) DEFAULT 1,
    dest_from_sbc_id INT,
    dest_destination_id INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (src_call_server_id) REFERENCES call_servers(id) ON DELETE SET NULL,
    FOREIGN KEY (dest_call_server_id) REFERENCES call_servers(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Intercoms
CREATE TABLE IF NOT EXISTS intercoms (
    id INT AUTO_INCREMENT PRIMARY KEY,
    branch_id INT,
    call_server_id INT,
    name VARCHAR(100) NOT NULL,
    extension VARCHAR(50),
    description VARCHAR(255),
    is_active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE SET NULL,
    FOREIGN KEY (call_server_id) REFERENCES call_servers(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
