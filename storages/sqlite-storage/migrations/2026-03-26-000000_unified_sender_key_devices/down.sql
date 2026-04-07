-- Restore the original two-table structure

CREATE TABLE skdm_recipients (
    group_jid TEXT NOT NULL,
    device_jid TEXT NOT NULL,
    device_id INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY (group_jid, device_jid, device_id)
);

CREATE INDEX idx_skdm_recipients_group ON skdm_recipients (group_jid, device_id);

CREATE TABLE sender_key_status (
    group_jid TEXT NOT NULL,
    participant TEXT NOT NULL,
    device_id INTEGER NOT NULL DEFAULT 1,
    marked_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY (group_jid, participant, device_id)
);

CREATE INDEX idx_sender_key_status_group ON sender_key_status (group_jid, device_id);

-- Migrate back: has_key=1 -> skdm_recipients, has_key=0 -> sender_key_status
INSERT OR IGNORE INTO skdm_recipients (group_jid, device_jid, device_id, created_at)
    SELECT group_jid, device_jid, device_id, updated_at FROM sender_key_devices WHERE has_key = 1;

INSERT OR IGNORE INTO sender_key_status (group_jid, participant, device_id, marked_at)
    SELECT group_jid, device_jid, device_id, updated_at FROM sender_key_devices WHERE has_key = 0;

DROP TABLE sender_key_devices;
