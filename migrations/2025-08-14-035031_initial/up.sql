CREATE TABLE identities (
    address TEXT PRIMARY KEY NOT NULL,
    key BLOB NOT NULL
);

CREATE TABLE sessions (
    address TEXT PRIMARY KEY NOT NULL,
    record BLOB NOT NULL
);

CREATE TABLE prekeys (
    id INTEGER PRIMARY KEY NOT NULL,
    key BLOB NOT NULL,
    uploaded BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE sender_keys (
    address TEXT PRIMARY KEY NOT NULL,
    record BLOB NOT NULL
);

CREATE TABLE app_state_keys (
    key_id BLOB PRIMARY KEY NOT NULL,
    key_data BLOB NOT NULL
);

CREATE TABLE app_state_versions (
    name TEXT PRIMARY KEY NOT NULL,
    state_data BLOB NOT NULL
);

CREATE TABLE app_state_mutation_macs (
    name TEXT NOT NULL,
    version BIGINT NOT NULL,
    index_mac BLOB NOT NULL,
    value_mac BLOB NOT NULL,
    PRIMARY KEY (name, index_mac)
);

CREATE TABLE device (
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

CREATE TABLE signed_prekeys (
    id INTEGER PRIMARY KEY NOT NULL,
    record BLOB NOT NULL
);

-- Mapping between LID (lightweight identity) users and PN (phone-number) users
-- Stores only the user part; server is implied by JID kind
CREATE TABLE lid_pn_mappings (
    lid_user TEXT PRIMARY KEY NOT NULL,
    pn_user TEXT NOT NULL
);

CREATE UNIQUE INDEX idx_pn_user ON lid_pn_mappings(pn_user);