use crate::crypto::key_pair::{KeyPair, PreKey};
use crate::types::jid::Jid;
use once_cell::sync::Lazy;
use prost::Message;
use serde::{Deserialize, Serialize};
use whatsapp_proto::whatsapp as wa;

// A static, lazily-initialized base payload
static BASE_CLIENT_PAYLOAD: Lazy<wa::ClientPayload> = Lazy::new(|| wa::ClientPayload {
    user_agent: Some(wa::client_payload::UserAgent {
        platform: Some(wa::client_payload::user_agent::Platform::Web as i32),
        release_channel: Some(wa::client_payload::user_agent::ReleaseChannel::Release as i32),
        app_version: Some(wa::client_payload::user_agent::AppVersion {
            primary: Some(2),
            secondary: Some(3000),
            tertiary: Some(1023868176),
            ..Default::default()
        }),
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
});

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

/// Core device data structure containing only platform-independent information
#[derive(Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: Option<Jid>,
    pub lid: Option<Jid>,
    pub registration_id: u32,
    pub noise_key: KeyPair,
    pub identity_key: KeyPair,
    pub signed_pre_key: PreKey,
    pub adv_secret_key: [u8; 32],
    pub account: Option<wa::AdvSignedDeviceIdentity>,
    pub push_name: String,
}

impl Device {
    /// Creates a new, unregistered device with fresh keys
    pub fn new() -> Self {
        use rand::RngCore;
        
        let identity_key = KeyPair::new();
        let signed_pre_key = identity_key.create_signed_prekey(1).unwrap();
        let mut adv_secret_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut adv_secret_key);

        Self {
            id: None,
            lid: None,
            registration_id: 3718719151,
            noise_key: KeyPair::new(),
            identity_key,
            signed_pre_key,
            adv_secret_key,
            account: None,
            push_name: String::new(),
        }
    }

    /// Gets client payload for handshake
    pub fn get_client_payload(&self) -> wa::ClientPayload {
        match &self.id {
            Some(jid) => self.get_login_payload(jid),
            None => self.get_registration_payload(),
        }
    }

    /// Helper function to get the login payload for a connected client
    fn get_login_payload(&self, jid: &Jid) -> wa::ClientPayload {
        let mut payload = BASE_CLIENT_PAYLOAD.clone();
        payload.username = jid.user.parse::<u64>().ok();
        payload.device = Some(jid.device as u32);
        payload.passive = Some(true);
        payload
    }

    /// Helper function to get the registration payload for a new client
    fn get_registration_payload(&self) -> wa::ClientPayload {
        let mut payload = BASE_CLIENT_PAYLOAD.clone();

        let device_props_bytes = DEVICE_PROPS.encode_to_vec();

        // Dynamically calculate the version hash
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
            e_keytype: Some(vec![5]), // DJB_TYPE
            e_ident: Some(self.identity_key.public_key.to_vec()),
            e_skey_id: Some({ self.signed_pre_key.key_id }.to_be_bytes()[1..].to_vec()), // 3-byte ID
            e_skey_val: Some(self.signed_pre_key.key_pair.public_key.to_vec()),
            e_skey_sig: Some(self.signed_pre_key.signature.unwrap().to_vec()),
            build_hash: Some(build_hash.to_vec()),
            device_props: Some(device_props_bytes),
        };

        payload.device_pairing_data = Some(reg_data);
        payload.passive = Some(false);
        payload.pull = Some(false);
        payload
    }
}