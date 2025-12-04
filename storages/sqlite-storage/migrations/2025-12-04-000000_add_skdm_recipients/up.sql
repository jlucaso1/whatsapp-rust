-- Create table to track which devices have received Sender Key Distribution Messages (SKDM) for each group
CREATE TABLE skdm_recipients (
    group_jid TEXT NOT NULL,
    device_jid TEXT NOT NULL,
    device_id INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY (group_jid, device_jid, device_id)
);

-- Index for fast lookups by group
CREATE INDEX idx_skdm_recipients_group ON skdm_recipients (group_jid, device_id);
