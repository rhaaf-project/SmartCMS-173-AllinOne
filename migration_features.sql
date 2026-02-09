-- Migration for new feature tables
CREATE TABLE IF NOT EXISTS black_lists (
    id INT AUTO_INCREMENT PRIMARY KEY,
    number VARCHAR(50) NOT NULL,
    description VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS conferences (
    id INT AUTO_INCREMENT PRIMARY KEY,
    conference_number VARCHAR(50) NOT NULL,
    conference_name VARCHAR(50) NOT NULL,
    user_pin VARCHAR(20),
    admin_pin VARCHAR(20),
    language VARCHAR(20) DEFAULT 'Inherit',
    join_message VARCHAR(50) DEFAULT 'None',
    leader_wait TINYINT(1) DEFAULT 1,
    leader_leave TINYINT(1) DEFAULT 1,
    talker_optimization TINYINT(1) DEFAULT 1,
    talker_detection TINYINT(1) DEFAULT 1,
    quiet_mode TINYINT(1) DEFAULT 0,
    user_count TINYINT(1) DEFAULT 1,
    user_join_leave TINYINT(1) DEFAULT 1,
    music_on_hold TINYINT(1) DEFAULT 1,
    music_on_hold_class VARCHAR(50) DEFAULT 'Inherit',
    allow_menu TINYINT(1) DEFAULT 1,
    record_conference TINYINT(1) DEFAULT 0,
    max_participants INT DEFAULT 0,
    mute_on_join TINYINT(1) DEFAULT 0,
    member_timeout INT DEFAULT 21600,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS custom_destinations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target VARCHAR(100) NOT NULL,
    description VARCHAR(255),
    notes TEXT,
    return_call TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS misc_destinations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    description VARCHAR(255) NOT NULL,
    dial VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
