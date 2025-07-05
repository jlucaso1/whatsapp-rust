// src/store/clientpayload.rs

use whatsapp_proto::whatsapp as wa;
use crate::types::jid::Jid;
use md5;
use once_cell::sync::Lazy;
use prost::Message;

// A static, lazily-initialized base payload, similar to the Go version.
pub static BASE_CLIENT_PAYLOAD: Lazy<wa::ClientPayload> = Lazy::new(|| wa::ClientPayload {
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

// Port of Go's `DeviceProps`
pub static DEVICE_PROPS: Lazy<wa::DeviceProps> = Lazy::new(|| wa::DeviceProps {
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

// Helper function to get the login payload for a connected client
pub fn get_login_payload(jid: &Jid) -> wa::ClientPayload {
    let mut payload = BASE_CLIENT_PAYLOAD.clone();
    payload.username = jid.user.parse::<u64>().ok();
    payload.device = Some(jid.device as u32);
    payload.passive = Some(true);
    payload
}

// Helper function to get the registration payload for a new client
pub fn get_registration_payload(
    reg_id: u32,
    identity_key_pub: &[u8; 32],
    signed_pre_key: &crate::crypto::key_pair::PreKey,
) -> wa::ClientPayload {
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
        e_regid: Some(reg_id.to_be_bytes().to_vec()),
        e_keytype: Some(vec![5]), // DJB_TYPE
        e_ident: Some(identity_key_pub.to_vec()),
        e_skey_id: Some({ signed_pre_key.key_id }.to_be_bytes()[1..].to_vec()), // 3-byte ID
        e_skey_val: Some(signed_pre_key.key_pair.public_key.to_vec()),
        e_skey_sig: Some(signed_pre_key.signature.unwrap().to_vec()),
        build_hash: Some(build_hash.to_vec()),
        device_props: Some(device_props_bytes),
        ..Default::default()
    };

    payload.device_pairing_data = Some(reg_data);
    payload.passive = Some(false);
    payload.pull = Some(false);
    payload
}
