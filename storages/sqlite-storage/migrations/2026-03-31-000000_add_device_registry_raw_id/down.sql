-- SQLite doesn't support DROP COLUMN in older versions, but newer SQLite (3.35+) does.
ALTER TABLE device_registry DROP COLUMN raw_id;
