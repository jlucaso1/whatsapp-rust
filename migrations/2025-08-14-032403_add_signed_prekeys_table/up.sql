-- Create signed_prekeys table to store Signal Protocol signed pre-keys
CREATE TABLE signed_prekeys (
    id INTEGER PRIMARY KEY NOT NULL,
    record BLOB NOT NULL
);
