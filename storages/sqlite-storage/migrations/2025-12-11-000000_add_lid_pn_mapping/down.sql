-- Remove edge_routing_info column from device table
-- SQLite doesn't support DROP COLUMN directly in older versions, but newer SQLite (3.35+) does
-- For compatibility, we create a new table without the column and migrate data
-- Drop the lid/phone mapping table and indexes so we can safely recreate the device table
DROP INDEX IF EXISTS idx_lid_pn_mapping_phone;
DROP TABLE IF EXISTS lid_pn_mapping;

-- Recreate the device table without the edge_routing_info column using an explicit schema copy
CREATE TABLE device_backup (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lid TEXT NOT NULL,
    pn TEXT NOT NULL,
    registration_id INTEGER NOT NULL,
    noise_key BLOB NOT NULL,
    identity_key BLOB NOT NULL,
    signed_pre_key BLOB NOT NULL,
    signed_pre_key_id INTEGER NOT NULL,
    signed_pre_key_signature BLOB NOT NULL,
    adv_secret_key BLOB NOT NULL,
    account BLOB,
    push_name TEXT NOT NULL DEFAULT '',
    app_version_primary INTEGER NOT NULL DEFAULT 0,
    app_version_secondary INTEGER NOT NULL DEFAULT 0,
    app_version_tertiary BIGINT NOT NULL DEFAULT 0,
    app_version_last_fetched_ms BIGINT NOT NULL DEFAULT 0
);

INSERT INTO device_backup (
    id,
    lid,
    pn,
    registration_id,
    noise_key,
    identity_key,
    signed_pre_key,
    signed_pre_key_id,
    signed_pre_key_signature,
    adv_secret_key,
    account,
    push_name,
    app_version_primary,
    app_version_secondary,
    app_version_tertiary,
    app_version_last_fetched_ms
)
SELECT
    id,
    lid,
    pn,
    registration_id,
    noise_key,
    identity_key,
    signed_pre_key,
    signed_pre_key_id,
    signed_pre_key_signature,
    adv_secret_key,
    account,
    push_name,
    app_version_primary,
    app_version_secondary,
    app_version_tertiary,
    app_version_last_fetched_ms
FROM device;

DROP TABLE device;
ALTER TABLE device_backup RENAME TO device;
