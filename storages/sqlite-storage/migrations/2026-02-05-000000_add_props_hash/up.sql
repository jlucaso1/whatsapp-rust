-- Add props_hash column to device table
-- Stores the hash from the last A/B props fetch to enable delta updates
ALTER TABLE device ADD COLUMN props_hash TEXT;
