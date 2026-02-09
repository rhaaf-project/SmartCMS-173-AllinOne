-- Create Turret Template & Group Tables
-- Run this SQL in db_ucx MariaDB database

-- 1. Turret Templates
CREATE TABLE IF NOT EXISTS `turret_templates` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `description` text DEFAULT NULL,
  `layout_json` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`layout_json`)),
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2. Turret Groups
CREATE TABLE IF NOT EXISTS `turret_groups` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `description` text DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. Turret Group Members
CREATE TABLE IF NOT EXISTS `turret_group_members` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `group_id` bigint(20) unsigned NOT NULL,
  `extension` varchar(20) NOT NULL,
  PRIMARY KEY (`id`),
  FOREIGN KEY (`group_id`) REFERENCES `turret_groups` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Sample Data: Template
INSERT INTO `turret_templates` (`name`, `description`, `layout_json`) VALUES
('Default Trader Layout', 'Standard layout for FX desk', '[
  {"id": "whatsapp", "label": "WhatsApp", "icon": "chat", "color": "#25d366", "bgColor": "rgba(37, 211, 102, 0.2)", "panel": "whatsapp"},
  {"id": "teams", "label": "Teams", "icon": "groups", "color": "#6264a7", "bgColor": "rgba(98, 100, 167, 0.2)", "panel": "teams"},
  null, null
]');

-- Sample Data: Group
INSERT INTO `turret_groups` (`name`, `description`) VALUES ('FX Desk Group', 'Group for Forex Traders');
SET @group_id = LAST_INSERT_ID();
INSERT INTO `turret_group_members` (`group_id`, `extension`) VALUES (@group_id, '1001'), (@group_id, '1002');
