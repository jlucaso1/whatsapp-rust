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

-- Step 4: Update all account-specific tables to include device_id in their primary keys
-- and add device_id = 1 for existing data

-- Recreate identities table with composite primary key
CREATE TABLE identities_new (
    address TEXT NOT NULL,
    key BLOB NOT NULL,
    device_id INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (address, device_id)
);
INSERT INTO identities_new (address, key, device_id) 
SELECT address, key, 1 FROM identities;
DROP TABLE identities;
ALTER TABLE identities_new RENAME TO identities;
CREATE INDEX idx_identities_device_id ON identities (device_id);

-- Recreate sessions table with composite primary key
CREATE TABLE sessions_new (
    address TEXT NOT NULL,
    record BLOB NOT NULL,
    device_id INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (address, device_id)
);
INSERT INTO sessions_new (address, record, device_id) 
SELECT address, record, 1 FROM sessions;
DROP TABLE sessions;
ALTER TABLE sessions_new RENAME TO sessions;
CREATE INDEX idx_sessions_device_id ON sessions (device_id);

-- Recreate prekeys table with composite primary key
CREATE TABLE prekeys_new (
    id INTEGER NOT NULL,
    key BLOB NOT NULL,
    uploaded BOOLEAN NOT NULL DEFAULT FALSE,
    device_id INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (id, device_id)
);
INSERT INTO prekeys_new (id, key, uploaded, device_id) 
SELECT id, key, uploaded, 1 FROM prekeys;
DROP TABLE prekeys;
ALTER TABLE prekeys_new RENAME TO prekeys;
CREATE INDEX idx_prekeys_device_id ON prekeys (device_id);

-- Recreate sender_keys table with composite primary key
CREATE TABLE sender_keys_new (
    address TEXT NOT NULL,
    record BLOB NOT NULL,
    device_id INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (address, device_id)
);
INSERT INTO sender_keys_new (address, record, device_id) 
SELECT address, record, 1 FROM sender_keys;
DROP TABLE sender_keys;
ALTER TABLE sender_keys_new RENAME TO sender_keys;
CREATE INDEX idx_sender_keys_device_id ON sender_keys (device_id);

-- Recreate signed_prekeys table with composite primary key
CREATE TABLE signed_prekeys_new (
    id INTEGER NOT NULL,
    record BLOB NOT NULL,
    device_id INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (id, device_id)
);
INSERT INTO signed_prekeys_new (id, record, device_id) 
SELECT id, record, 1 FROM signed_prekeys;
DROP TABLE signed_prekeys;
ALTER TABLE signed_prekeys_new RENAME TO signed_prekeys;
CREATE INDEX idx_signed_prekeys_device_id ON signed_prekeys (device_id);

-- Recreate app_state_keys table with composite primary key
CREATE TABLE app_state_keys_new (
    key_id BLOB NOT NULL,
    key_data BLOB NOT NULL,
    device_id INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (key_id, device_id)
);
INSERT INTO app_state_keys_new (key_id, key_data, device_id) 
SELECT key_id, key_data, 1 FROM app_state_keys;
DROP TABLE app_state_keys;
ALTER TABLE app_state_keys_new RENAME TO app_state_keys;
CREATE INDEX idx_app_state_keys_device_id ON app_state_keys (device_id);

-- Recreate app_state_versions table with composite primary key
CREATE TABLE app_state_versions_new (
    name TEXT NOT NULL,
    state_data BLOB NOT NULL,
    device_id INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (name, device_id)
);
INSERT INTO app_state_versions_new (name, state_data, device_id) 
SELECT name, state_data, 1 FROM app_state_versions;
DROP TABLE app_state_versions;
ALTER TABLE app_state_versions_new RENAME TO app_state_versions;
CREATE INDEX idx_app_state_versions_device_id ON app_state_versions (device_id);

-- Recreate app_state_mutation_macs table with composite primary key
CREATE TABLE app_state_mutation_macs_new (
    name TEXT NOT NULL,
    version BIGINT NOT NULL,
    index_mac BLOB NOT NULL,
    value_mac BLOB NOT NULL,
    device_id INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (name, index_mac, device_id)
);
INSERT INTO app_state_mutation_macs_new (name, version, index_mac, value_mac, device_id) 
SELECT name, version, index_mac, value_mac, 1 FROM app_state_mutation_macs;
DROP TABLE app_state_mutation_macs;
ALTER TABLE app_state_mutation_macs_new RENAME TO app_state_mutation_macs;
CREATE INDEX idx_app_state_mutation_macs_device_id ON app_state_mutation_macs (device_id);
