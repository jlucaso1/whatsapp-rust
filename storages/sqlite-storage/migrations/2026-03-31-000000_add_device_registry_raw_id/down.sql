-- Remove raw_id column using table-rebuild (compatible with SQLite < 3.35)
CREATE TABLE device_registry_backup AS SELECT
    user_id, devices_json, timestamp, phash, device_id, updated_at
FROM device_registry;

DROP TABLE device_registry;

CREATE TABLE device_registry (
    user_id TEXT NOT NULL,
    devices_json TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    phash TEXT,
    device_id INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, device_id)
);

INSERT INTO device_registry SELECT * FROM device_registry_backup;
DROP TABLE device_registry_backup;
