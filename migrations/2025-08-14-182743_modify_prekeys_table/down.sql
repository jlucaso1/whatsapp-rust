-- Revert prekeys table to original schema
DROP TABLE prekeys;

-- Restore from backup if it exists
CREATE TABLE prekeys (
    id INTEGER PRIMARY KEY NOT NULL,
    record BLOB NOT NULL
);

-- Restore backed up data if any exists
INSERT INTO prekeys SELECT id, record FROM prekeys_backup WHERE EXISTS (SELECT 1 FROM prekeys_backup);

-- Clean up backup table
DROP TABLE IF EXISTS prekeys_backup;
