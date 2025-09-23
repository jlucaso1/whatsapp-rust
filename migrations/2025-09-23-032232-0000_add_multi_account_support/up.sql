-- Multi-account support: Add auto-incrementing id to device table and device_id to all account tables
-- SQLite doesn't support modifying column constraints directly, so we need to recreate the device table

-- Step 1: Create new device table with proper schema (id as primary key)
CREATE TABLE device_new (
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

-- Step 2: Copy data from old table to new table (setting id = 1 for existing device)
INSERT INTO device_new (id, lid, pn, registration_id, noise_key, identity_key, signed_pre_key, 
                        signed_pre_key_id, signed_pre_key_signature, adv_secret_key, account, 
                        push_name, app_version_primary, app_version_secondary, app_version_tertiary, 
                        app_version_last_fetched_ms)
SELECT 1, lid, pn, registration_id, noise_key, identity_key, signed_pre_key, 
       signed_pre_key_id, signed_pre_key_signature, adv_secret_key, account, 
       push_name, app_version_primary, app_version_secondary, app_version_tertiary, 
       app_version_last_fetched_ms
FROM device;

-- Step 3: Drop old table and rename new table
DROP TABLE device;
ALTER TABLE device_new RENAME TO device;

-- Step 4: Add device_id column to all account-specific tables and set to 1 for existing data
-- identities table
ALTER TABLE identities ADD COLUMN device_id INTEGER NOT NULL DEFAULT 1;
CREATE INDEX idx_identities_device_id ON identities (device_id);

-- sessions table  
ALTER TABLE sessions ADD COLUMN device_id INTEGER NOT NULL DEFAULT 1;
CREATE INDEX idx_sessions_device_id ON sessions (device_id);

-- prekeys table
ALTER TABLE prekeys ADD COLUMN device_id INTEGER NOT NULL DEFAULT 1;
CREATE INDEX idx_prekeys_device_id ON prekeys (device_id);

-- sender_keys table
ALTER TABLE sender_keys ADD COLUMN device_id INTEGER NOT NULL DEFAULT 1;
CREATE INDEX idx_sender_keys_device_id ON sender_keys (device_id);

-- signed_prekeys table
ALTER TABLE signed_prekeys ADD COLUMN device_id INTEGER NOT NULL DEFAULT 1;
CREATE INDEX idx_signed_prekeys_device_id ON signed_prekeys (device_id);

-- app_state_keys table
ALTER TABLE app_state_keys ADD COLUMN device_id INTEGER NOT NULL DEFAULT 1;
CREATE INDEX idx_app_state_keys_device_id ON app_state_keys (device_id);

-- app_state_versions table
ALTER TABLE app_state_versions ADD COLUMN device_id INTEGER NOT NULL DEFAULT 1;
CREATE INDEX idx_app_state_versions_device_id ON app_state_versions (device_id);

-- app_state_mutation_macs table
ALTER TABLE app_state_mutation_macs ADD COLUMN device_id INTEGER NOT NULL DEFAULT 1;
CREATE INDEX idx_app_state_mutation_macs_device_id ON app_state_mutation_macs (device_id);
