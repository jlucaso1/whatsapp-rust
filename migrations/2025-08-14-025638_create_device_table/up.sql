-- Create device table to store WhatsApp device information
CREATE TABLE device (
    id INTEGER PRIMARY KEY CHECK (id = 1), -- Single device per database
    jid TEXT,                              -- Device JID (if registered)
    lid TEXT,                              -- Linked device ID
    registration_id INTEGER NOT NULL,      -- Signal Protocol registration ID
    noise_key BLOB NOT NULL,               -- Noise Protocol key pair (serialized)
    identity_key BLOB NOT NULL,            -- Signal Protocol identity key pair (serialized)
    signed_pre_key BLOB NOT NULL,          -- Signal Protocol signed pre-key pair (serialized)
    signed_pre_key_id INTEGER NOT NULL,    -- Signed pre-key ID
    signed_pre_key_signature BLOB NOT NULL, -- Signature of signed pre-key (64 bytes)
    adv_secret_key BLOB NOT NULL,          -- ADV secret key (32 bytes)
    account BLOB,                          -- Encoded AdvSignedDeviceIdentity (optional)
    push_name TEXT NOT NULL DEFAULT '',    -- Display name for the device
    processed_messages BLOB                -- Serialized list of processed message keys
);
