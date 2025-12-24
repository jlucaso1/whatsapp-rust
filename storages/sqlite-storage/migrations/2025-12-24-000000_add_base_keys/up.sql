-- Base key tracking for retry collision detection.
-- Stores session base keys to detect when a sender hasn't regenerated their
-- session keys despite receiving our retry receipts (matches WhatsApp Web behavior).

CREATE TABLE base_keys (
    address TEXT NOT NULL,
    message_id TEXT NOT NULL,
    base_key BLOB NOT NULL,
    device_id INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY (address, message_id, device_id)
);

CREATE INDEX idx_base_keys_device ON base_keys (device_id);
