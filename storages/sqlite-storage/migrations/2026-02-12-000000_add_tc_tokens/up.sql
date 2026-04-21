-- Trusted Contact (tcToken) storage.
-- Stores privacy tokens per contact for 1:1 messaging trust verification.
-- Matches WhatsApp Web's Chat.tcToken / tcTokenTimestamp / tcTokenSenderTimestamp fields.

CREATE TABLE tc_tokens (
    jid TEXT NOT NULL,
    token BLOB NOT NULL,
    token_timestamp INTEGER NOT NULL,
    sender_timestamp INTEGER,
    device_id INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY (jid, device_id)
);

CREATE INDEX idx_tc_tokens_timestamp ON tc_tokens (token_timestamp, device_id);
