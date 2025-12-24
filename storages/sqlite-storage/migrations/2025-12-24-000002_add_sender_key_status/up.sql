-- Sender key status tracking for lazy deletion pattern.
-- Matches WhatsApp Web's markForgetSenderKey behavior.
-- Instead of immediately deleting sender keys on retry, we mark them for
-- regeneration and consume the marks on the next group send.

CREATE TABLE sender_key_status (
    group_jid TEXT NOT NULL,
    participant TEXT NOT NULL,
    device_id INTEGER NOT NULL DEFAULT 1,
    marked_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY (group_jid, participant, device_id)
);

CREATE INDEX idx_sender_key_status_group ON sender_key_status (group_jid, device_id);
