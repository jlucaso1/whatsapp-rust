-- migrations/2025-08-14-023634_create_initial_schema/up.sql

-- Stores Signal Protocol identity keys
CREATE TABLE identities (
    address TEXT PRIMARY KEY NOT NULL,
    key BLOB NOT NULL
);

-- Stores Signal Protocol session records
CREATE TABLE sessions (
    address TEXT PRIMARY KEY NOT NULL,
    record BLOB NOT NULL
);

-- Stores Signal Protocol pre-keys
CREATE TABLE prekeys (
    id INTEGER PRIMARY KEY NOT NULL,
    record BLOB NOT NULL
);

-- Stores Signal Protocol group sender keys
CREATE TABLE sender_keys (
    address TEXT PRIMARY KEY NOT NULL,
    record BLOB NOT NULL
);

-- Stores App State synchronization keys
CREATE TABLE app_state_keys (
    key_id BLOB PRIMARY KEY NOT NULL,
    key_data BLOB NOT NULL
);

-- Stores the version and hash state for different App State collections
CREATE TABLE app_state_versions (
    name TEXT PRIMARY KEY NOT NULL,
    state_data BLOB NOT NULL
);
