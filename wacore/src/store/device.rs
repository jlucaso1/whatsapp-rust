use crate::libsignal::protocol::{IdentityKeyPair, KeyPair};
use once_cell::sync::Lazy;
use prost::Message;
use rand::TryRngCore;
use rand_core::OsRng;
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
            .into_iter()
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

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessedMessageKey {
    pub to: Jid,
    pub id: String,
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

static DEVICE_PROPS: Lazy<wa::DeviceProps> = Lazy::new(|| wa::DeviceProps {
    os: Some("rust".to_string()),
    version: Some(wa::device_props::AppVersion {
        primary: Some(0),
        secondary: Some(1),
        tertiary: Some(0),
        ..Default::default()
    }),
    platform_type: Some(wa::device_props::PlatformType::Unknown as i32),
    require_full_sync: Some(false),
    ..Default::default()
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
}

impl Default for Device {
    fn default() -> Self {
        Self::new()
    }
}

impl Device {
    pub fn new() -> Self {
        use rand::RngCore;

        let identity_key_pair = IdentityKeyPair::generate(&mut OsRng.unwrap_err());

        let identity_key: KeyPair = KeyPair::new(
            *identity_key_pair.public_key(),
            *identity_key_pair.private_key(),
        );
        let signed_pre_key = KeyPair::generate(&mut OsRng.unwrap_err());
        let signature_box = identity_key_pair
            .private_key()
            .calculate_signature(
                &signed_pre_key.public_key.serialize(),
                &mut OsRng.unwrap_err(),
            )
            .unwrap();
        let signed_pre_key_signature: [u8; 64] = signature_box.as_ref().try_into().unwrap();
        let mut adv_secret_key = [0u8; 32];
        rand::rng().fill_bytes(&mut adv_secret_key);

        Self {
            pn: None,
            lid: None,
            registration_id: 3718719151,
            noise_key: KeyPair::generate(&mut OsRng.unwrap_err()),
            identity_key,
            signed_pre_key,
            signed_pre_key_id: 1,
            signed_pre_key_signature,
            adv_secret_key,
            account: None,
            push_name: String::new(),
            app_version_primary: 2,
            app_version_secondary: 3000,
            app_version_tertiary: 1023868176,
            app_version_last_fetched_ms: 0,
        }
    }

    pub fn is_ready_for_presence(&self) -> bool {
        self.pn.is_some() && !self.push_name.is_empty()
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

        let device_props_bytes = DEVICE_PROPS.encode_to_vec();

        let version = payload
            .user_agent
            .as_ref()
            .unwrap()
            .app_version
            .as_ref()
            .unwrap();
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
