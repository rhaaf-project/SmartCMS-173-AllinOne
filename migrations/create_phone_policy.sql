-- Phone Directory & Policy Tables
-- Run on db_ucx

-- 1. Phone Directories (Phonebook)
CREATE TABLE IF NOT EXISTS `phone_directories` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `company` varchar(100) DEFAULT NULL,
  `phones` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`phones`)),
  `email` varchar(255) DEFAULT NULL,
  `notes` text DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2. Turret Policies
CREATE TABLE IF NOT EXISTS `turret_policies` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `max_channels` int DEFAULT 4,
  `allow_recording` tinyint(1) DEFAULT 1,
  `allow_intercom` tinyint(1) DEFAULT 1,
  `allow_group_talk` tinyint(1) DEFAULT 1,
  `allow_external` tinyint(1) DEFAULT 1,
  `description` text DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Sample Data
INSERT INTO `phone_directories` (`name`, `company`, `phones`, `email`) VALUES
('John Doe', 'Acme Corp', '["021-1234567", "0812-1234567"]', 'john@acme.com'),
('Jane Smith', 'XYZ Bank', '["021-7654321"]', 'jane@xyz.com');

INSERT INTO `turret_policies` (`name`, `max_channels`, `description`) VALUES
('Standard Trader', 4, 'Default policy for traders'),
('Senior Trader', 8, 'Extended channels for senior traders');
