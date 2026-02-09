CREATE TABLE IF NOT EXISTS `outbound_dial_patterns` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `outbound_routing_id` bigint(20) unsigned NOT NULL,
  `prepend` varchar(50) DEFAULT NULL,
  `prefix` varchar(50) DEFAULT NULL,
  `match_pattern` varchar(50) DEFAULT NULL,
  `caller_id` varchar(50) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `outbound_dial_patterns_routing_id_foreign` (`outbound_routing_id`),
  CONSTRAINT `outbound_dial_patterns_routing_id_foreign` FOREIGN KEY (`outbound_routing_id`) REFERENCES `outbound_routings` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `static_routes` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `destination` varchar(50) NOT NULL COMMENT 'CIDR notation e.g. 192.168.1.0/24',
  `gateway` varchar(50) NOT NULL COMMENT 'Gateway IP address',
  `interface_name` varchar(20) DEFAULT 'eth0',
  `metric` int(11) DEFAULT 100,
  `device_type` enum('call_server','sbc','recording') NOT NULL COMMENT 'Type of device to apply route',
  `device_id` bigint(20) unsigned NOT NULL COMMENT 'ID of the target device',
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `firewall_rules` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `protocol` enum('TCP','UDP','ICMP','ALL') DEFAULT 'TCP',
  `port` varchar(50) NOT NULL COMMENT 'Port or range e.g. 5060 or 10000-20000',
  `source` varchar(50) DEFAULT 'Any',
  `action` enum('ACCEPT','DROP','REJECT') DEFAULT 'ACCEPT',
  `priority` int(11) DEFAULT 100,
  `device_type` enum('call_server','sbc','recording') NOT NULL,
  `device_id` bigint(20) unsigned NOT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
