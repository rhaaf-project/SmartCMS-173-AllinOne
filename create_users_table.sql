-- =====================================================
-- CMS Users Table for SmartCMS Angular
-- Database: db_ucx (MariaDB)
-- Created: 2026-02-02
-- =====================================================

-- Drop existing table if needed (uncomment if you want fresh start)
-- DROP TABLE IF EXISTS users;

CREATE TABLE IF NOT EXISTS users (
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

-- Insert initial users with bcrypt hashed passwords
-- Passwords:
--   root@smartcms.local: Maja1234
--   admin@smartx.local: admin123  
--   cmsadmin@smartx.local: Admin@123

INSERT INTO users (name, email, password, role, is_active) VALUES
('Root Admin', 'root@smartcms.local', '$2y$10$HfzIhGCCaxqyaIdGgjARSuBT7u6o5CtbD3Yzr5G3r2wz.x1hKRzh6', 'admin', 1),
('Admin User', 'admin@smartx.local', '$2y$10$N9qo8uLOickgx2ZMRZoMye7VmI6dKMC3Gxn1Hx5z3kRlLq2GVq0Gy', 'admin', 1),
('CMS Admin', 'cmsadmin@smartx.local', '$2y$10$dXJ3SW6G7P50lGmMkkmwe.7K6LQOAHvK8Q6zJ1Ku8F3xWfN6K3Eqe', 'admin', 1)
ON DUPLICATE KEY UPDATE name=VALUES(name), password=VALUES(password), role=VALUES(role);
