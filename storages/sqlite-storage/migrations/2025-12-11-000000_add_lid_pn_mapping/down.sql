-- Remove edge_routing_info column from device table
-- SQLite doesn't support DROP COLUMN directly in older versions, but newer SQLite (3.35+) does
-- For compatibility, we create a new table without the column and migrate data
CREATE TABLE device_backup AS SELECT
    id, lid, pn, registration_id, noise_key, identity_key, signed_pre_key,
    signed_pre_key_id, signed_pre_key_signature, adv_secret_key, account,
    push_name, app_version_primary, app_version_secondary, app_version_tertiary,
    app_version_last_fetched_ms
FROM device;
DROP TABLE device;
ALTER TABLE device_backup RENAME TO device;

DROP INDEX IF EXISTS idx_lid_pn_mapping_phone;
DROP TABLE IF EXISTS lid_pn_mapping;
