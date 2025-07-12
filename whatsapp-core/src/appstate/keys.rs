use crate::crypto::hkdf;

pub const WAPATCH_CRITICAL_BLOCK: &str = "critical_block";
pub const WAPATCH_CRITICAL_UNBLOCK_LOW: &str = "critical_unblock_low";
pub const WAPATCH_REGULAR: &str = "regular";
pub const WAPATCH_REGULAR_LOW: &str = "regular_low";
pub const WAPATCH_REGULAR_HIGH: &str = "regular_high";

pub const ALL_PATCH_NAMES: [&str; 5] = [
    WAPATCH_CRITICAL_BLOCK,
    WAPATCH_CRITICAL_UNBLOCK_LOW,
    WAPATCH_REGULAR,
    WAPATCH_REGULAR_LOW,
    WAPATCH_REGULAR_HIGH,
];

#[derive(Clone)]
pub struct ExpandedAppStateKeys {
    pub index: [u8; 32],
    pub value_encryption: [u8; 32],
    pub value_mac: [u8; 32],
    pub snapshot_mac: [u8; 32],
    pub patch_mac: [u8; 32],
}

pub fn expand_app_state_keys(key_data: &[u8]) -> ExpandedAppStateKeys {
    let expanded = hkdf::sha256(key_data, None, b"WhatsApp Mutation Keys", 160).unwrap();
    ExpandedAppStateKeys {
        index: expanded[0..32].try_into().unwrap(),
        value_encryption: expanded[32..64].try_into().unwrap(),
        value_mac: expanded[64..96].try_into().unwrap(),
        snapshot_mac: expanded[96..128].try_into().unwrap(),
        patch_mac: expanded[128..160].try_into().unwrap(),
    }
}