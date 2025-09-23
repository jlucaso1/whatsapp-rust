-- This migration reverses the multi-account support changes
-- WARNING: This will remove the device_id columns and revert to single-account schema

-- Drop indexes first, then remove device_id columns from all account-specific tables
DROP INDEX IF EXISTS idx_app_state_mutation_macs_device_id;
DROP INDEX IF EXISTS idx_app_state_versions_device_id;
DROP INDEX IF EXISTS idx_app_state_keys_device_id;
DROP INDEX IF EXISTS idx_signed_prekeys_device_id;
DROP INDEX IF EXISTS idx_sender_keys_device_id;
DROP INDEX IF EXISTS idx_prekeys_device_id;
DROP INDEX IF EXISTS idx_sessions_device_id;
DROP INDEX IF EXISTS idx_identities_device_id;

-- SQLite doesn't support DROP COLUMN directly, so we need to recreate tables
-- Recreate app_state_mutation_macs without device_id
CREATE TABLE app_state_mutation_macs_new (
    name TEXT NOT NULL,
    version BIGINT NOT NULL,
    index_mac BLOB NOT NULL,
    value_mac BLOB NOT NULL,
    PRIMARY KEY (name, index_mac)
);
INSERT INTO app_state_mutation_macs_new SELECT name, version, index_mac, value_mac FROM app_state_mutation_macs;
DROP TABLE app_state_mutation_macs;
ALTER TABLE app_state_mutation_macs_new RENAME TO app_state_mutation_macs;

-- Recreate app_state_versions without device_id
CREATE TABLE app_state_versions_new (
    name TEXT PRIMARY KEY NOT NULL,
    state_data BLOB NOT NULL
);
INSERT INTO app_state_versions_new SELECT name, state_data FROM app_state_versions;
DROP TABLE app_state_versions;
ALTER TABLE app_state_versions_new RENAME TO app_state_versions;

-- Recreate app_state_keys without device_id
CREATE TABLE app_state_keys_new (
    key_id BLOB PRIMARY KEY NOT NULL,
    key_data BLOB NOT NULL
);
INSERT INTO app_state_keys_new SELECT key_id, key_data FROM app_state_keys;
DROP TABLE app_state_keys;
ALTER TABLE app_state_keys_new RENAME TO app_state_keys;

-- Recreate signed_prekeys without device_id
CREATE TABLE signed_prekeys_new (
    id INTEGER PRIMARY KEY NOT NULL,
    record BLOB NOT NULL
);
INSERT INTO signed_prekeys_new SELECT id, record FROM signed_prekeys;
DROP TABLE signed_prekeys;
ALTER TABLE signed_prekeys_new RENAME TO signed_prekeys;

-- Recreate sender_keys without device_id
CREATE TABLE sender_keys_new (
    address TEXT PRIMARY KEY NOT NULL,
    record BLOB NOT NULL
);
INSERT INTO sender_keys_new SELECT address, record FROM sender_keys;
DROP TABLE sender_keys;
ALTER TABLE sender_keys_new RENAME TO sender_keys;

-- Recreate prekeys without device_id
CREATE TABLE prekeys_new (
    id INTEGER PRIMARY KEY NOT NULL,
    key BLOB NOT NULL,
    uploaded BOOLEAN NOT NULL DEFAULT FALSE
);
INSERT INTO prekeys_new SELECT id, key, uploaded FROM prekeys;
DROP TABLE prekeys;
ALTER TABLE prekeys_new RENAME TO prekeys;

-- Recreate sessions without device_id
CREATE TABLE sessions_new (
    address TEXT PRIMARY KEY NOT NULL,
    record BLOB NOT NULL
);
INSERT INTO sessions_new SELECT address, record FROM sessions;
DROP TABLE sessions;
ALTER TABLE sessions_new RENAME TO sessions;

-- Recreate identities without device_id
CREATE TABLE identities_new (
    address TEXT PRIMARY KEY NOT NULL,
    key BLOB NOT NULL
);
INSERT INTO identities_new SELECT address, key FROM identities;
DROP TABLE identities;
ALTER TABLE identities_new RENAME TO identities;

-- Revert device table to original schema (lid as primary key)
CREATE TABLE device_old (
    lid TEXT PRIMARY KEY NOT NULL,
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

-- Copy data back (excluding the id column)
INSERT INTO device_old (lid, pn, registration_id, noise_key, identity_key, signed_pre_key, 
                        signed_pre_key_id, signed_pre_key_signature, adv_secret_key, account, 
                        push_name, app_version_primary, app_version_secondary, app_version_tertiary, 
                        app_version_last_fetched_ms)
SELECT lid, pn, registration_id, noise_key, identity_key, signed_pre_key, 
       signed_pre_key_id, signed_pre_key_signature, adv_secret_key, account, 
       push_name, app_version_primary, app_version_secondary, app_version_tertiary, 
       app_version_last_fetched_ms
FROM device;

-- Replace the device table
DROP TABLE device;
ALTER TABLE device_old RENAME TO device;
