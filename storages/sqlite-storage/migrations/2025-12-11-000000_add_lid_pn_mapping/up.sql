-- LID to Phone Number mapping table
-- Stores the mapping between WhatsApp's Linked ID (LID) and phone numbers
-- This is used for Signal address resolution and session management
CREATE TABLE lid_pn_mapping (
    lid TEXT NOT NULL,                      -- LID user part (e.g., "100000012345678")
    phone_number TEXT NOT NULL,             -- Phone number user part (e.g., "559980000001")
    created_at BIGINT NOT NULL,            -- Unix timestamp when mapping was first learned
    learning_source TEXT NOT NULL,          -- Source of the mapping (usync, peer_pn_message, etc.)
    updated_at BIGINT NOT NULL,            -- Unix timestamp of last update
    device_id INTEGER NOT NULL,             -- Device ID for multi-account support
    PRIMARY KEY (lid, device_id),
    FOREIGN KEY(device_id) REFERENCES device(id) ON DELETE CASCADE
);

-- Index for reverse lookup (phone number -> LID)
CREATE INDEX idx_lid_pn_mapping_phone ON lid_pn_mapping(phone_number, device_id);

-- Add edge_routing_info column to device table
-- This stores the edge routing info received from WhatsApp servers for optimized reconnection
ALTER TABLE device ADD COLUMN edge_routing_info BLOB;
