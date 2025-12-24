-- WhatsApp Web Architecture Alignment
-- This migration adds tables required for proper WhatsApp Web protocol alignment:
-- 1. base_keys - Retry collision detection
-- 2. device_registry - Device list caching with phash support
-- 3. sender_key_status - Lazy sender key deletion pattern

--------------------------------------------------------------------------------
-- Base key tracking for retry collision detection.
-- Stores session base keys to detect when a sender hasn't regenerated their
-- session keys despite receiving our retry receipts (matches WhatsApp Web behavior).
--------------------------------------------------------------------------------
CREATE TABLE base_keys (
    address TEXT NOT NULL,
    message_id TEXT NOT NULL,
    base_key BLOB NOT NULL,
    device_id INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY (address, message_id, device_id)
);

CREATE INDEX idx_base_keys_device ON base_keys (device_id);

--------------------------------------------------------------------------------
-- Device registry for tracking known devices per user.
-- Matches WhatsApp Web's DeviceListRecord structure.
-- Used to validate device existence before processing retry receipts.
--------------------------------------------------------------------------------
CREATE TABLE device_registry (
    user_id TEXT NOT NULL,
    devices_json TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    phash TEXT,
    device_id INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY (user_id, device_id)
);

CREATE INDEX idx_device_registry_timestamp ON device_registry (timestamp);
CREATE INDEX idx_device_registry_device ON device_registry (device_id);
CREATE INDEX idx_device_registry_updated_at ON device_registry (updated_at);

--------------------------------------------------------------------------------
-- Sender key status tracking for lazy deletion pattern.
-- Matches WhatsApp Web's markForgetSenderKey behavior.
-- Instead of immediately deleting sender keys on retry, we mark them for
-- regeneration and consume the marks on the next group send.
--------------------------------------------------------------------------------
CREATE TABLE sender_key_status (
    group_jid TEXT NOT NULL,
    participant TEXT NOT NULL,
    device_id INTEGER NOT NULL DEFAULT 1,
    marked_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY (group_jid, participant, device_id)
);

CREATE INDEX idx_sender_key_status_group ON sender_key_status (group_jid, device_id);
