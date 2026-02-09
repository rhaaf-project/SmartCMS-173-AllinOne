-- System Config table for dynamic settings
-- Run this on db_ucx to enable dynamic configuration

CREATE TABLE IF NOT EXISTS system_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100) NOT NULL UNIQUE,
    config_value TEXT,
    description VARCHAR(255),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Insert default values
INSERT INTO system_config (config_key, config_value, description) VALUES
('sip_server', '103.154.80.172', 'SIP/VoIP Server IP Address'),
('sip_port', '5060', 'SIP Server Port'),
('stun_server', 'stun:stun.l.google.com:19302', 'STUN Server for WebRTC NAT traversal')
ON DUPLICATE KEY UPDATE config_value = VALUES(config_value);
