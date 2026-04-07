use redb::TableDefinition;

pub const IDENTITIES: TableDefinition<&str, &[u8]> = TableDefinition::new("identities");

pub const SESSIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("sessions");

pub const PREKEYS: TableDefinition<u64, &[u8]> = TableDefinition::new("prekeys");

pub const PREKEYS_UPLOADED: TableDefinition<u64, bool> = TableDefinition::new("prekeys_uploaded");

pub const SIGNED_PREKEYS: TableDefinition<u64, &[u8]> = TableDefinition::new("signed_prekeys");

pub const SENDER_KEYS: TableDefinition<&str, &[u8]> = TableDefinition::new("sender_keys");

pub const APP_STATE_KEYS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("app_state_keys");

pub const APP_STATE_VERSIONS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("app_state_versions");

pub const MUTATION_MACS: TableDefinition<&str, &[u8]> = TableDefinition::new("mutation_macs");

pub const LID_PN_MAPPING: TableDefinition<&str, &[u8]> = TableDefinition::new("lid_pn_mapping");

pub const PN_LID_INDEX: TableDefinition<&str, &str> = TableDefinition::new("pn_lid_index");

pub const BASE_KEYS: TableDefinition<&str, &[u8]> = TableDefinition::new("base_keys");

pub const DEVICE_REGISTRY: TableDefinition<&str, &[u8]> = TableDefinition::new("device_registry");

pub const DEVICE_DATA: TableDefinition<i32, &[u8]> = TableDefinition::new("device_data");

pub const DEVICE_COUNTER: TableDefinition<&str, i32> = TableDefinition::new("device_counter");

pub const SENDER_KEY_DEVICES: TableDefinition<&str, &[u8]> =
    TableDefinition::new("sender_key_devices");

pub const TC_TOKENS: TableDefinition<&str, &[u8]> = TableDefinition::new("tc_tokens");

pub const SENT_MESSAGES: TableDefinition<&str, &[u8]> = TableDefinition::new("sent_messages");

pub const APP_STATE_KEY_IDS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("app_state_key_ids");
