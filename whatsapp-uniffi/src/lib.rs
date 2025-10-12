#![allow(clippy::all)]

uniffi::setup_scaffolding!();

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

/// Returns a placeholder device status record for testing bindings.
#[uniffi::export]
pub fn sample_device_status() -> PublicDeviceStatusProxy {
    use whatsapp_rust::types::public::PublicDeviceStatus;

    let status = PublicDeviceStatus {
        jid: "12345@s.whatsapp.net".to_string(),
        display_name: Some("Sample".to_string()),
        connected: true,
        unread_chats: 0,
    };

    status.into()
}

/// Returns a placeholder event payload for testing bindings.
#[uniffi::export]
pub fn sample_event() -> PublicEventProxy {
    use whatsapp_rust::types::public::PublicEvent;

    let event = PublicEvent {
        category: "connected".to_string(),
        payload_json: "{}".to_string(),
    };

    event.into()
}
