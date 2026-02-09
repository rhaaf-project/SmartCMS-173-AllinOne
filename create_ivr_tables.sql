-- Create Announcements Table
CREATE TABLE IF NOT EXISTS announcements (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    filename VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create Recordings Table
CREATE TABLE IF NOT EXISTS recordings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    filename VARCHAR(255),
    type ENUM('system', 'user') DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- IVR Table
-- Note: Running these one by one. If they fail because column exists, that is fine.
ALTER TABLE ivr ADD COLUMN alert_info VARCHAR(255);
ALTER TABLE ivr ADD COLUMN volume_override INT DEFAULT 0;
ALTER TABLE ivr ADD COLUMN invalid_retries INT DEFAULT 3;
ALTER TABLE ivr ADD COLUMN invalid_retry_recording INT;
ALTER TABLE ivr ADD COLUMN append_announcement_to_invalid TINYINT(1) DEFAULT 1;
ALTER TABLE ivr ADD COLUMN return_on_invalid TINYINT(1) DEFAULT 0;
ALTER TABLE ivr ADD COLUMN invalid_recording INT;
ALTER TABLE ivr ADD COLUMN invalid_destination VARCHAR(255);
ALTER TABLE ivr ADD COLUMN timeout_retries INT DEFAULT 3;
ALTER TABLE ivr ADD COLUMN timeout_retry_recording INT;
ALTER TABLE ivr ADD COLUMN append_announcement_to_timeout TINYINT(1) DEFAULT 1;
ALTER TABLE ivr ADD COLUMN return_on_timeout TINYINT(1) DEFAULT 0;
ALTER TABLE ivr ADD COLUMN timeout_recording INT;
ALTER TABLE ivr ADD COLUMN timeout_destination VARCHAR(255);
ALTER TABLE ivr ADD COLUMN return_to_ivr_after_vm TINYINT(1) DEFAULT 1;

-- Create IVR Entries Table
CREATE TABLE IF NOT EXISTS ivr_entries (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ivr_id INT,
    digits VARCHAR(10) NOT NULL,
    destination VARCHAR(255),
    return_to_ivr TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (ivr_id) REFERENCES ivr(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert sample data for announcements/recordings
INSERT IGNORE INTO announcements (name, description) VALUES ('Welcome Message', 'Default welcome greeting');
INSERT IGNORE INTO recordings (name, description, type) VALUES ('Invalid Option', 'Played when invalid key pressed', 'system');
