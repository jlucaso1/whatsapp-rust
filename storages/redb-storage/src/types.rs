use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableDevice {
    pub lid: Option<String>,
    pub pn: Option<String>,
    pub registration_id: u32,
    pub noise_key: Vec<u8>,
    pub identity_key: Vec<u8>,
    pub signed_pre_key: Vec<u8>,
    pub signed_pre_key_id: u32,
    pub signed_pre_key_signature: Vec<u8>,
    pub adv_secret_key: Vec<u8>,
    pub account: Option<Vec<u8>>,
    pub push_name: String,
    pub app_version_primary: u32,
    pub app_version_secondary: u32,
    pub app_version_tertiary: u32,
    pub app_version_last_fetched_ms: i64,
    pub edge_routing_info: Option<Vec<u8>>,
}
