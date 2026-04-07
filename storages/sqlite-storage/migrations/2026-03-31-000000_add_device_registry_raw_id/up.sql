-- Add raw_id column to device_registry for ADV identity change detection.
-- When raw_id changes between notifications, all sessions and sender keys
-- for the user must be cleared (matches WA Web's clearDeviceRecord).
ALTER TABLE device_registry ADD COLUMN raw_id INTEGER;
