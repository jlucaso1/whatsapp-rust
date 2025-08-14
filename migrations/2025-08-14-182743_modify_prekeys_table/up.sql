-- Modify prekeys table to support robust pre-key management
-- Change from storing protobuf record to storing key data directly with upload tracking

-- First, backup any existing data
CREATE TABLE prekeys_backup AS SELECT * FROM prekeys;

-- Drop the existing table
DROP TABLE prekeys;

-- Create the new table with the improved schema
CREATE TABLE prekeys (
    id INTEGER PRIMARY KEY NOT NULL,
    key BLOB NOT NULL,
    uploaded BOOLEAN NOT NULL DEFAULT FALSE
);

-- Note: We can't easily migrate the old protobuf records to the new key format
-- so we'll start with an empty table. This is acceptable since pre-keys are
-- regenerated on connection anyway.
