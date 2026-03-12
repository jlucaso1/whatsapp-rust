-- Add next_pre_key_id counter to device table.
-- Persistent monotonic counter for pre-key ID generation (matches WA Web's NEXT_PK_ID).
-- Default 0 signals migration needed (will be resolved from MAX(prekeys.id) on first upload).
ALTER TABLE device ADD COLUMN next_pre_key_id INTEGER NOT NULL DEFAULT 0;
