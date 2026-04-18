//! Wire-tag invariant tests for enums that derive `WireEnum`.
//!
//! The derive owns `Serialize`/`Deserialize`, which delegate to `as_str()` /
//! `TryFrom<&str>` — so the JSON representation MUST be exactly what the
//! `#[wire = "..."]` attribute declares. No PascalCase discriminator, no
//! serde `rename_all`, no hand-written impls.
//!
//! Cases cover unit-string mode (with and without `#[wire_fallback]`),
//! int mode (see `TempBanReason` / `ConnectFailureReason` serialization as
//! i32), and the sanity check on `EditAttribute` whose wire strings diverge
//! from variant names. Tagged mode is covered end-to-end inside
//! `stanza::groups::tests`.

use wacore::stanza::business::BusinessNotificationType;
use wacore::stanza::devices::DeviceNotificationType;
use wacore::types::events::{
    BusinessUpdateType, ConnectFailureReason, DecryptFailMode, DeviceListUpdateType, TempBanReason,
    UnavailableType,
};
use wacore::types::lid_pn::LearningSource;
use wacore::types::message::{AddressingMode, EditAttribute, MessageCategory};

fn assert_roundtrip<T>(values: &[T])
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de> + PartialEq + std::fmt::Debug + Clone,
{
    for v in values {
        let json = serde_json::to_value(v).expect("serialize");
        let back: T = serde_json::from_value(json.clone()).expect("deserialize");
        assert_eq!(&back, v, "round-trip mismatch for JSON {json}");
    }
}

#[test]
fn device_notification_type_uses_wire_strings() {
    for (value, expected) in [
        (DeviceNotificationType::Add, "add"),
        (DeviceNotificationType::Remove, "remove"),
        (DeviceNotificationType::Update, "update"),
    ] {
        assert_eq!(serde_json::to_value(value).unwrap(), expected);
    }
    assert_roundtrip(&[
        DeviceNotificationType::Add,
        DeviceNotificationType::Remove,
        DeviceNotificationType::Update,
    ]);
}

#[test]
fn device_list_update_type_uses_wire_strings() {
    for (value, expected) in [
        (DeviceListUpdateType::Add, "add"),
        (DeviceListUpdateType::Remove, "remove"),
        (DeviceListUpdateType::Update, "update"),
    ] {
        assert_eq!(serde_json::to_value(value).unwrap(), expected);
    }
}

#[test]
fn business_notification_type_uses_wire_strings() {
    let expected = [
        (BusinessNotificationType::RemoveJid, "remove_jid"),
        (BusinessNotificationType::RemoveHash, "remove_hash"),
        (
            BusinessNotificationType::VerifiedNameJid,
            "verified_name_jid",
        ),
        (
            BusinessNotificationType::VerifiedNameHash,
            "verified_name_hash",
        ),
        (BusinessNotificationType::Profile, "profile"),
        (BusinessNotificationType::ProfileHash, "profile_hash"),
        (BusinessNotificationType::Product, "product"),
        (BusinessNotificationType::Collection, "collection"),
        (BusinessNotificationType::Subscriptions, "subscriptions"),
        (BusinessNotificationType::Unknown, "unknown"),
    ];
    for (value, expected) in expected {
        assert_eq!(serde_json::to_value(value).unwrap(), expected);
    }
}

#[test]
fn business_update_type_is_snake_case() {
    assert_eq!(
        serde_json::to_value(BusinessUpdateType::RemovedAsBusiness).unwrap(),
        "removed_as_business"
    );
    assert_eq!(
        serde_json::to_value(BusinessUpdateType::VerifiedNameChanged).unwrap(),
        "verified_name_changed"
    );
    assert_eq!(
        serde_json::to_value(BusinessUpdateType::Unknown).unwrap(),
        "unknown"
    );
}

#[test]
fn decrypt_fail_mode_is_lowercase() {
    assert_eq!(serde_json::to_value(DecryptFailMode::Show).unwrap(), "show");
    assert_eq!(serde_json::to_value(DecryptFailMode::Hide).unwrap(), "hide");
}

#[test]
fn unavailable_type_is_snake_case() {
    assert_eq!(
        serde_json::to_value(UnavailableType::Unknown).unwrap(),
        "unknown"
    );
    assert_eq!(
        serde_json::to_value(UnavailableType::ViewOnce).unwrap(),
        "view_once"
    );
}

#[test]
fn addressing_mode_matches_wire() {
    assert_eq!(serde_json::to_value(AddressingMode::Pn).unwrap(), "pn");
    assert_eq!(serde_json::to_value(AddressingMode::Lid).unwrap(), "lid");
    assert_roundtrip(&[AddressingMode::Pn, AddressingMode::Lid]);
}

#[test]
fn learning_source_matches_wire() {
    assert_eq!(
        serde_json::to_value(LearningSource::Usync).unwrap(),
        "usync"
    );
    assert_eq!(
        serde_json::to_value(LearningSource::BlocklistActive).unwrap(),
        "blocklist_active"
    );
    assert_eq!(
        serde_json::to_value(LearningSource::DeviceNotification).unwrap(),
        "device_notification"
    );
}

#[test]
fn edit_attribute_uses_wire_strings_not_variant_names() {
    // Regression: variants like `MessageEdit` used to serialize as
    // `"MessageEdit"` because the enum derived `Serialize` without
    // `rename_all`, even though its wire string was `"1"`.
    assert_eq!(
        serde_json::to_value(EditAttribute::MessageEdit).unwrap(),
        "1"
    );
    assert_eq!(
        serde_json::to_value(EditAttribute::SenderRevoke).unwrap(),
        "7"
    );
    assert_eq!(serde_json::to_value(EditAttribute::Empty).unwrap(), "");
}

#[test]
fn message_category_fallback_serializes_literal() {
    assert_eq!(serde_json::to_value(MessageCategory::Peer).unwrap(), "peer");
    assert_eq!(serde_json::to_value(MessageCategory::Empty).unwrap(), "");
    assert_eq!(
        serde_json::to_value(MessageCategory::Other("custom".into())).unwrap(),
        "custom"
    );
}

#[test]
fn temp_ban_reason_serializes_as_int_and_roundtrips() {
    for (value, expected) in [
        (TempBanReason::SentToTooManyPeople, 101),
        (TempBanReason::BlockedByUsers, 102),
        (TempBanReason::CreatedTooManyGroups, 103),
        (TempBanReason::SentTooManySameMessage, 104),
        (TempBanReason::BroadcastList, 106),
        (TempBanReason::Unknown(999), 999),
    ] {
        let json = serde_json::to_value(&value).unwrap();
        assert_eq!(json, expected);
        let back: TempBanReason = serde_json::from_value(json).unwrap();
        assert_eq!(back, value);
    }
}

#[test]
fn connect_failure_reason_serializes_as_int_and_roundtrips() {
    for (value, expected) in [
        (ConnectFailureReason::Generic, 400),
        (ConnectFailureReason::LoggedOut, 401),
        (ConnectFailureReason::TempBanned, 402),
        (ConnectFailureReason::ServiceUnavailable, 503),
        (ConnectFailureReason::Unknown(999), 999),
    ] {
        let json = serde_json::to_value(value).unwrap();
        assert_eq!(json, expected);
        let back: ConnectFailureReason = serde_json::from_value(json).unwrap();
        assert_eq!(back, value);
    }
}
