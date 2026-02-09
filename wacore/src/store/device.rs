use crate::libsignal::protocol::{IdentityKeyPair, KeyPair};
use once_cell::sync::Lazy;
use prost::Message;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use wacore_binary::jid::Jid;
use waproto::whatsapp as wa;

pub mod key_pair_serde {
    use super::KeyPair;
    use crate::libsignal::protocol::{PrivateKey, PublicKey};
    use serde::{self, Deserializer, Serializer};

    pub fn serialize<S>(key_pair: &KeyPair, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes: Vec<u8> = key_pair
            .private_key
            .serialize()
            .iter()
            .copied()
            .chain(key_pair.public_key.public_key_bytes().iter().copied())
            .collect();
        serializer.serialize_bytes(&bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<KeyPair, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: &[u8] = serde::Deserialize::deserialize(deserializer)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::invalid_length(bytes.len(), &"64"));
        }
        let private_key = PrivateKey::deserialize(&bytes[0..32])
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        let public_key = PublicKey::from_djb_public_key_bytes(&bytes[32..64])
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        Ok(KeyPair::new(public_key, private_key))
    }
}

fn build_base_client_payload(
    app_version: wa::client_payload::user_agent::AppVersion,
) -> wa::ClientPayload {
    wa::ClientPayload {
        user_agent: Some(wa::client_payload::UserAgent {
            platform: Some(wa::client_payload::user_agent::Platform::Web as i32),
            release_channel: Some(wa::client_payload::user_agent::ReleaseChannel::Release as i32),
            app_version: Some(app_version),
            mcc: Some("000".to_string()),
            mnc: Some("000".to_string()),
            os_version: Some("0.1.0".to_string()),
            manufacturer: Some("".to_string()),
            device: Some("Desktop".to_string()),
            os_build_number: Some("0.1.0".to_string()),
            locale_language_iso6391: Some("en".to_string()),
            locale_country_iso31661_alpha2: Some("en".to_string()),
            ..Default::default()
        }),
        web_info: Some(wa::client_payload::WebInfo {
            web_sub_platform: Some(wa::client_payload::web_info::WebSubPlatform::WebBrowser as i32),
            ..Default::default()
        }),
        connect_type: Some(wa::client_payload::ConnectType::WifiUnknown as i32),
        connect_reason: Some(wa::client_payload::ConnectReason::UserActivated as i32),
        ..Default::default()
    }
}

pub static DEVICE_PROPS: Lazy<wa::DeviceProps> = Lazy::new(|| wa::DeviceProps {
    os: Some("rust".to_string()),
    version: Some(wa::device_props::AppVersion {
        primary: Some(0),
        secondary: Some(1),
        tertiary: Some(0),
        ..Default::default()
    }),
    platform_type: Some(wa::device_props::PlatformType::Unknown as i32),
    require_full_sync: Some(true),
    history_sync_config: Some(wa::device_props::HistorySyncConfig {
        full_sync_days_limit: Some(30),
        inline_initial_payload_in_e2_ee_msg: Some(true),
        storage_quota_mb: Some(10240),
        ..Default::default()
    }),
});

#[derive(Clone, Serialize, Deserialize)]
pub struct Device {
    pub pn: Option<Jid>,
    pub lid: Option<Jid>,
    pub registration_id: u32,
    #[serde(with = "key_pair_serde")]
    pub noise_key: KeyPair,
    #[serde(with = "key_pair_serde")]
    pub identity_key: KeyPair,
    #[serde(with = "key_pair_serde")]
    pub signed_pre_key: KeyPair,
    pub signed_pre_key_id: u32,
    #[serde(with = "BigArray")]
    pub signed_pre_key_signature: [u8; 64],
    pub adv_secret_key: [u8; 32],
    pub account: Option<wa::AdvSignedDeviceIdentity>,
    pub push_name: String,
    pub app_version_primary: u32,
    pub app_version_secondary: u32,
    pub app_version_tertiary: u32,
    pub app_version_last_fetched_ms: i64,
    #[serde(skip)]
    pub device_props: wa::DeviceProps,
    /// Edge routing info received from server, used for optimized reconnection.
    /// When present, this should be sent as a pre-intro before the Noise handshake.
    #[serde(default)]
    pub edge_routing_info: Option<Vec<u8>>,
    /// Hash from the last props (A/B experiment config) fetch.
    /// Sent on subsequent connects to enable delta updates instead of full fetches.
    #[serde(default)]
    pub props_hash: Option<String>,
}

impl Default for Device {
    fn default() -> Self {
        Self::new()
    }
}

impl Device {
    pub fn new() -> Self {
        use rand::Rng;
        use rand::RngCore;

        let mut rng = rand::rng();
        let identity_key_pair = IdentityKeyPair::generate(&mut rng);

        let identity_key: KeyPair = KeyPair::new(
            *identity_key_pair.public_key(),
            identity_key_pair.private_key().clone(),
        );
        let signed_pre_key = KeyPair::generate(&mut rng);
        let signature_box = identity_key_pair
            .private_key()
            .calculate_signature(&signed_pre_key.public_key.serialize(), &mut rng)
            .expect("signing with valid Ed25519 key should succeed");
        let signed_pre_key_signature: [u8; 64] = signature_box
            .as_ref()
            .try_into()
            .expect("Ed25519 signature is always 64 bytes");
        let mut adv_secret_key = [0u8; 32];
        rng.fill_bytes(&mut adv_secret_key);

        Self {
            pn: None,
            lid: None,
            registration_id: rng.random_range(1..=2147483647),
            noise_key: KeyPair::generate(&mut rng),
            identity_key,
            signed_pre_key,
            signed_pre_key_id: 1,
            signed_pre_key_signature,
            adv_secret_key,
            account: None,
            push_name: String::new(),
            app_version_primary: 2,
            app_version_secondary: 3000,
            app_version_tertiary: 1031424117,
            app_version_last_fetched_ms: 0,
            device_props: DEVICE_PROPS.clone(),
            edge_routing_info: None,
            props_hash: None,
        }
    }

    /// Returns the default OS string used for device props
    pub fn default_os() -> &'static str {
        "rust"
    }

    /// Returns the default device props version
    pub fn default_device_props_version() -> wa::device_props::AppVersion {
        wa::device_props::AppVersion {
            primary: Some(0),
            secondary: Some(1),
            tertiary: Some(0),
            ..Default::default()
        }
    }

    pub fn is_ready_for_presence(&self) -> bool {
        self.pn.is_some() && !self.push_name.is_empty()
    }

    pub fn set_device_props(
        &mut self,
        os: Option<String>,
        version: Option<wa::device_props::AppVersion>,
        platform_type: Option<wa::device_props::PlatformType>,
    ) {
        if let Some(os) = os {
            self.device_props.os = Some(os);
        }
        if let Some(version) = version {
            self.device_props.version = Some(version);
        }
        if let Some(platform_type) = platform_type {
            self.device_props.platform_type = Some(platform_type as i32);
        }
    }

    pub fn get_client_payload(&self) -> wa::ClientPayload {
        match &self.pn {
            Some(jid) => self.get_login_payload(jid),
            None => self.get_registration_payload(),
        }
    }

    fn get_login_payload(&self, jid: &Jid) -> wa::ClientPayload {
        let app_version = wa::client_payload::user_agent::AppVersion {
            primary: Some(self.app_version_primary),
            secondary: Some(self.app_version_secondary),
            tertiary: Some(self.app_version_tertiary),
            ..Default::default()
        };
        let mut payload = build_base_client_payload(app_version);
        payload.username = jid.user.parse::<u64>().ok();
        payload.device = Some(jid.device as u32);
        payload.passive = Some(true);
        payload
    }

    fn get_registration_payload(&self) -> wa::ClientPayload {
        let app_version = wa::client_payload::user_agent::AppVersion {
            primary: Some(self.app_version_primary),
            secondary: Some(self.app_version_secondary),
            tertiary: Some(self.app_version_tertiary),
            ..Default::default()
        };
        let mut payload = build_base_client_payload(app_version);

        let device_props_bytes = self.device_props.encode_to_vec();

        let version = payload
            .user_agent
            .as_ref()
            .expect("payload should have user_agent")
            .app_version
            .as_ref()
            .expect("user_agent should have app_version");
        let version_str = format!(
            "{}.{}.{}",
            version.primary(),
            version.secondary(),
            version.tertiary()
        );
        let build_hash: [u8; 16] = md5::compute(version_str.as_bytes()).into();

        let reg_data = wa::client_payload::DevicePairingRegistrationData {
            e_regid: Some(self.registration_id.to_be_bytes().to_vec()),
            e_keytype: Some(vec![5]),
            e_ident: Some(self.identity_key.public_key.public_key_bytes().to_vec()),
            e_skey_id: Some(self.signed_pre_key_id.to_be_bytes()[1..].to_vec()),
            e_skey_val: Some(self.signed_pre_key.public_key.public_key_bytes().to_vec()),
            e_skey_sig: Some(self.signed_pre_key_signature.to_vec()),
            build_hash: Some(build_hash.to_vec()),
            device_props: Some(device_props_bytes),
        };

        payload.device_pairing_data = Some(reg_data);
        payload.passive = Some(false);
        payload.pull = Some(false);
        payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registration_id_range() {
        for _ in 0..1000 {
            let device = Device::new();
            assert!(device.registration_id >= 1);
            assert!(device.registration_id <= 2147483647);
        }
    }
}
