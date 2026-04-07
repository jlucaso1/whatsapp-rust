-- Add NCT salt column to device table.
-- Server-provisioned salt for computing cstoken (HMAC-SHA256 fallback privacy token).
-- NULL means no salt has been provisioned yet.
ALTER TABLE device ADD COLUMN nct_salt BLOB;
