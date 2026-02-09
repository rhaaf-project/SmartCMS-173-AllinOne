-- Usage Statistics Table for Usage Report Feature
-- Created: 2026-02-04

-- Create the usage_statistics table
CREATE TABLE IF NOT EXISTS `usage_statistics` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `date` DATE NOT NULL,
  `branch_id` INT NULL,
  `call_server_id` INT NULL,
  `extension_number` VARCHAR(20) NOT NULL,
  
  -- Line calls
  `line_inbound` INT DEFAULT 0,
  `line_outbound` INT DEFAULT 0,
  
  -- Extension-to-extension calls
  `ext_inbound` INT DEFAULT 0,
  `ext_outbound` INT DEFAULT 0,
  
  -- VPW (Virtual Private Wire)
  `vpw_inbound` INT DEFAULT 0,
  `vpw_outbound` INT DEFAULT 0,
  
  -- CAS calls
  `cas_inbound` INT DEFAULT 0,
  `cas_outbound` INT DEFAULT 0,
  
  -- SIP/3rd Party
  `sip_inbound` INT DEFAULT 0,
  `sip_outbound` INT DEFAULT 0,
  
  -- Total talk time (in seconds)
  `total_time_inbound` INT DEFAULT 0,
  `total_time_outbound` INT DEFAULT 0,
  
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  
  UNIQUE KEY `unique_daily_ext` (`date`, `call_server_id`, `extension_number`),
  KEY `idx_date` (`date`),
  KEY `idx_branch` (`branch_id`),
  KEY `idx_call_server` (`call_server_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert sample data matching boss's screenshot
-- Using branch_id=1 (KAI Cimahi), call_server_id=3 (SmartUCX-2-KAI, IP: 103.154.81.102)
-- Date: today

INSERT INTO `usage_statistics` 
(`date`, `branch_id`, `call_server_id`, `extension_number`, 
 `line_inbound`, `line_outbound`, `ext_inbound`, `ext_outbound`,
 `vpw_inbound`, `vpw_outbound`, `cas_inbound`, `cas_outbound`,
 `sip_inbound`, `sip_outbound`, `total_time_inbound`, `total_time_outbound`) 
VALUES
-- Row 1: 8001 - Line: 4 in, 5 out
(CURDATE(), 1, 3, '8001', 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 1932, 43960),
-- Row 2: 8002 - Line: 1 in, 4 out
(CURDATE(), 1, 3, '8002', 1, 4, 0, 0, 0, 0, 0, 0, 0, 0, 1933, 43961),
-- Row 3: 8101 - Ext: 3 in, 10 out
(CURDATE(), 1, 3, '8101', 0, 0, 3, 10, 0, 0, 0, 0, 0, 0, 794, 43962),
-- Row 4: 8102 - Ext: 0 in, 2 out
(CURDATE(), 1, 3, '8102', 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 1935, 43963),
-- Row 5: 8201 - VPW: 7 in, 2 out
(CURDATE(), 1, 3, '8201', 0, 0, 0, 0, 7, 2, 0, 0, 0, 0, 1936, 43964),
-- Row 6: 8202 - VPW: 1 in, 0 out
(CURDATE(), 1, 3, '8202', 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1937, 43965),
-- Row 7: 8301 - CAS: 3 in, 7 out
(CURDATE(), 1, 3, '8301', 0, 0, 0, 0, 0, 0, 3, 7, 0, 0, 1938, 43966),
-- Row 8: 8302 - CAS: 3 in, 5 out
(CURDATE(), 1, 3, '8302', 0, 0, 0, 0, 0, 0, 3, 5, 0, 0, 1939, 43967),
-- Row 9: 7001 - SIP: 32 in, 45 out
(CURDATE(), 1, 3, '7001', 0, 0, 0, 0, 0, 0, 0, 0, 32, 45, 1940, 43968),
-- Row 10: 7002 - SIP: 12 in, 6 out
(CURDATE(), 1, 3, '7002', 0, 0, 0, 0, 0, 0, 0, 0, 12, 6, 1941, 43969);
