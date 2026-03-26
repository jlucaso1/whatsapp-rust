-- Unify skdm_recipients (positive tracking) and sender_key_status (forget marks)
-- into a single per-device sender key tracking table, matching WA Web's
-- participant.senderKey Map<deviceJid, boolean> model.

CREATE TABLE sender_key_devices (
    group_jid  TEXT    NOT NULL,
    device_jid TEXT    NOT NULL,
    has_key    INTEGER NOT NULL DEFAULT 0,
    device_id  INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY (group_jid, device_jid, device_id)
);

CREATE INDEX idx_sender_key_devices_group ON sender_key_devices (group_jid, device_id);

-- Migrate positive tracking (devices that have received SKDM)
INSERT OR IGNORE INTO sender_key_devices (group_jid, device_jid, device_id, has_key, updated_at)
    SELECT group_jid, device_jid, device_id, 1, created_at FROM skdm_recipients;

-- Migrate forget marks (devices needing fresh SKDM). OR REPLACE ensures
-- forget marks override positive entries for the same device.
INSERT OR REPLACE INTO sender_key_devices (group_jid, device_jid, device_id, has_key, updated_at)
    SELECT group_jid, participant, device_id, 0, marked_at FROM sender_key_status;

DROP TABLE skdm_recipients;
DROP TABLE sender_key_status;
