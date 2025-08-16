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

CREATE TABLE device (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    jid TEXT,
    lid TEXT,
    registration_id INTEGER NOT NULL,
    noise_key BLOB NOT NULL,
    identity_key BLOB NOT NULL,
    signed_pre_key BLOB NOT NULL,
    signed_pre_key_id INTEGER NOT NULL,
    signed_pre_key_signature BLOB NOT NULL,
    adv_secret_key BLOB NOT NULL,
    account BLOB,
    push_name TEXT NOT NULL DEFAULT '',
    processed_messages BLOB
);

CREATE TABLE signed_prekeys (
    id INTEGER PRIMARY KEY NOT NULL,
    record BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY NOT NULL,
    data BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS chat_conversations (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT,
    display_name TEXT,
    last_msg_timestamp INTEGER,
    unread_count INTEGER,
    archived INTEGER,
    pinned INTEGER,
    created_at INTEGER
);

CREATE TABLE IF NOT EXISTS chat_participants (
    conversation_id TEXT NOT NULL,
    jid TEXT NOT NULL,
    is_admin INTEGER,
    PRIMARY KEY(conversation_id, jid),
    FOREIGN KEY(conversation_id) REFERENCES chat_conversations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS chat_messages (
    conversation_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    server_timestamp INTEGER,
    sender_jid TEXT,
    message_blob BLOB NOT NULL,
    PRIMARY KEY(conversation_id, message_id),
    FOREIGN KEY(conversation_id) REFERENCES chat_conversations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_chat_conversations_unread ON chat_conversations(unread_count);