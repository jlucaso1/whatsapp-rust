-- Add index on updated_at for efficient cleanup queries
CREATE INDEX IF NOT EXISTS idx_device_registry_updated_at ON device_registry (updated_at);
