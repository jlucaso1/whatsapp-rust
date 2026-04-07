-- Remove props_hash column from device table
-- SQLite doesn't support DROP COLUMN before 3.35.0, so we recreate the table

CREATE TABLE device_backup AS SELECT
    id, lid, pn, registration_id, noise_key, identity_key,
    signed_pre_key, signed_pre_key_id, signed_pre_key_signature,
    adv_secret_key, account, push_name,
    app_version_primary, app_version_secondary, app_version_tertiary,
    app_version_last_fetched_ms, edge_routing_info
FROM device;

DROP TABLE device;

CREATE TABLE device (
    id INTEGER NOT NULL PRIMARY KEY,
    lid TEXT NOT NULL DEFAULT '',
    pn TEXT NOT NULL DEFAULT '',
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
    app_version_last_fetched_ms BIGINT NOT NULL DEFAULT 0,
    edge_routing_info BLOB
);

INSERT INTO device SELECT * FROM device_backup;
DROP TABLE device_backup;
