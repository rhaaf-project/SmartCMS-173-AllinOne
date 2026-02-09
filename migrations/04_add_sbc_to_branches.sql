-- Migration: Add sbc_id column to branches table
-- This allows tracking which branches have SBC connections

-- Check if column exists before adding
SET @column_exists = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS 
    WHERE TABLE_SCHEMA = DATABASE() 
    AND TABLE_NAME = 'branches' 
    AND COLUMN_NAME = 'sbc_id'
);

-- Only add if not exists
SET @sql = IF(@column_exists = 0, 
    'ALTER TABLE branches ADD COLUMN sbc_id INT DEFAULT NULL AFTER call_server_id',
    'SELECT "Column sbc_id already exists"'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add foreign key constraint (if column was added)
-- Note: Using separate ALTER to avoid issues if FK already exists
-- ALTER TABLE branches ADD CONSTRAINT fk_branches_sbc FOREIGN KEY (sbc_id) REFERENCES call_servers(id) ON DELETE SET NULL;
