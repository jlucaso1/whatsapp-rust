-- Sent message store for retry handling.
-- Replaces the in-memory recent_messages moka cache, matching WhatsApp Web's
-- pattern of reading from IndexedDB (getMessageTable) on retry receipt.

CREATE TABLE sent_messages (
    chat_jid TEXT NOT NULL,
    message_id TEXT NOT NULL,
    payload BLOB NOT NULL,
    device_id INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY (chat_jid, message_id, device_id)
);

CREATE INDEX idx_sent_messages_created ON sent_messages (created_at, device_id);
