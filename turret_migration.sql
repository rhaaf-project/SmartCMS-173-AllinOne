-- Create turret tables for server 171
CREATE TABLE IF NOT EXISTS turret_user_phonebooks (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    turret_user_id BIGINT NOT NULL,
    name VARCHAR(255) NOT NULL,
    phone VARCHAR(50) NOT NULL,
    company VARCHAR(255),
    email VARCHAR(255),
    notes TEXT,
    is_favourite BOOLEAN DEFAULT FALSE,
    is_archived BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_turret_user (turret_user_id)
);

CREATE TABLE IF NOT EXISTS turret_channel_states (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    turret_user_id BIGINT NOT NULL,
    channel_key VARCHAR(20) NOT NULL,
    contact_name VARCHAR(255),
    extension VARCHAR(50),
    volume_in INT DEFAULT 50,
    volume_out INT DEFAULT 50,
    is_ptt BOOLEAN DEFAULT FALSE,
    group_ids JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_user_channel (turret_user_id, channel_key),
    INDEX idx_turret_user (turret_user_id)
);

CREATE TABLE IF NOT EXISTS turret_user_preferences (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    turret_user_id BIGINT NOT NULL,
    preference_key VARCHAR(100) NOT NULL,
    preference_value JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_user_pref (turret_user_id, preference_key),
    INDEX idx_turret_user (turret_user_id)
);
