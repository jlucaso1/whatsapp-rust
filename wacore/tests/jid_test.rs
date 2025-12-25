use std::str::FromStr;
use wacore_binary::jid::{Jid, JidExt, SERVER_JID};

#[test]
fn test_jid_parsing_and_serialization() {
    let jid_str = format!("1234567890@{}", SERVER_JID);
    let jid = Jid::from_str(&jid_str).expect("test JID should be valid");
    assert_eq!(jid.user, "1234567890");
    assert_eq!(jid.server, SERVER_JID);
    assert_eq!(jid.agent, 0);
    assert_eq!(jid.device, 0);
    assert_eq!(jid.to_string(), jid_str);
    assert!(!jid.is_ad());
    assert!(!jid.is_group());

    let ad_jid_str = format!("1234567890:12@{}", SERVER_JID);
    let ad_jid = Jid::from_str(&ad_jid_str).expect("test JID should be valid");
    assert_eq!(ad_jid.user, "1234567890");
    assert_eq!(ad_jid.device, 12);
    assert_eq!(ad_jid.agent, 0);
    assert!(ad_jid.is_ad());
    assert_eq!(ad_jid.to_string(), ad_jid_str);

    let group_jid_str = "123-456@g.us";
    let group_jid = Jid::from_str(group_jid_str).expect("test JID should be valid");
    assert_eq!(group_jid.user, "123-456");
    assert_eq!(group_jid.server, "g.us");
    assert!(group_jid.is_group());
    assert_eq!(group_jid.to_string(), group_jid_str);

    let server_jid_str = SERVER_JID;
    let server_jid = Jid::from_str(server_jid_str).expect("test JID should be valid");
    assert!(server_jid.user.is_empty());
    assert_eq!(server_jid.server, SERVER_JID);
    // Server-only JIDs should NOT have @ prefix (matches WhatsApp Web behavior)
    assert_eq!(server_jid.to_string(), SERVER_JID);
}

#[test]
fn test_invalid_jid_parsing() {
    assert!(Jid::from_str("invalidjid").is_err());

    assert!(Jid::from_str("user@server:device").is_ok());
}

#[test]
fn test_is_ad_logic() {
    let jid_ad = Jid::from_str(&format!("123:1@{}", SERVER_JID)).expect("test JID should be valid");
    let jid_non_ad =
        Jid::from_str(&format!("123@{}", SERVER_JID)).expect("test JID should be valid");
    let jid_group = Jid::from_str("456@g.us").expect("test JID should be valid");

    assert!(jid_ad.is_ad());
    assert!(!jid_non_ad.is_ad());
    assert!(!jid_group.is_ad());
}

#[test]
fn test_legacy_and_agent_jid_parsing() {
    // Test case 1: Legacy companion device JID (e.g., from an older WhatsApp Web)
    // This is the primary failing case. The parser incorrectly identifies '.13' as an agent.
    let legacy_jid_str = format!("1234567890.13@{}", SERVER_JID);
    let legacy_jid = Jid::from_str(&legacy_jid_str).expect("test JID should be valid");
    assert_eq!(
        legacy_jid.user, "1234567890",
        "Legacy JID user part is incorrect"
    );
    assert_eq!(legacy_jid.device, 13, "Legacy JID device part should be 13");
    assert_eq!(legacy_jid.agent, 0, "Legacy JID agent part should be 0");
    assert_eq!(
        legacy_jid.server, SERVER_JID,
        "Legacy JID server part is incorrect"
    );

    // Test case 2: Modern companion device JID (for comparison)
    let modern_jid_str = format!("1234567890:5@{}", SERVER_JID);
    let modern_jid = Jid::from_str(&modern_jid_str).expect("test JID should be valid");
    assert_eq!(
        modern_jid.user, "1234567890",
        "Modern JID user part is incorrect"
    );
    assert_eq!(modern_jid.device, 5, "Modern JID device part should be 5");
    assert_eq!(modern_jid.agent, 0, "Modern JID agent part should be 0");

    // Test case 3: LID JID with dot in user part (without device)
    // LID user identifiers can contain dots that are part of the identity.
    // The dot should NOT be parsed as an agent separator for LID JIDs.
    let lid_nodot_str = "987654321.1@lid";
    let lid_nodot = Jid::from_str(lid_nodot_str).expect("test JID should be valid");
    assert_eq!(
        lid_nodot.user, "987654321.1",
        "LID user part with dot should be preserved"
    );
    assert_eq!(
        lid_nodot.agent, 0,
        "LID agent should be 0 (dots are not agent separators)"
    );
    assert_eq!(lid_nodot.device, 0, "LID device part should be 0");
    assert_eq!(lid_nodot.server, "lid", "LID server part is incorrect");
}

#[test]
fn test_lid_jid_with_dot_in_user_part() {
    // This is the problematic JID from the logs. The user part is "100000000000001.1".
    // The old parser would incorrectly split this, creating user="100000000000001" and agent=1.
    let lid_jid_str = "100000000000001.1:75@lid";
    let lid_jid = Jid::from_str(lid_jid_str).expect("test JID should be valid");

    // Assert that the user part is parsed correctly, including the dot.
    assert_eq!(
        lid_jid.user, "100000000000001.1",
        "LID user part with a dot was parsed incorrectly"
    );

    // Assert that the agent is not incorrectly parsed from the user part.
    assert_eq!(
        lid_jid.agent, 0,
        "LID JIDs should not have an agent part parsed from a dot"
    );

    // Assert that the device is still parsed correctly.
    assert_eq!(lid_jid.device, 75, "LID device part was parsed incorrectly");

    // Assert the server is correct.
    assert_eq!(lid_jid.server, "lid", "LID server part is incorrect");

    // CRITICAL: Test that to_protocol_address matches WhatsApp Web's format
    // WhatsApp Web uses: {user}[:device]@{server}.0
    // The device is encoded in the name, and device_id is always 0
    use wacore::types::jid::JidExt as CoreJidExt;
    let protocol_addr = lid_jid.to_protocol_address();
    assert_eq!(
        protocol_addr.name(),
        "100000000000001.1:75@lid",
        "ProtocolAddress name should match WhatsApp Web's SignalAddress format"
    );
    assert_eq!(
        u32::from(protocol_addr.device_id()),
        0,
        "ProtocolAddress device_id should always be 0 (device encoded in name)"
    );
    assert_eq!(
        protocol_addr.to_string(),
        "100000000000001.1:75@lid.0",
        "ProtocolAddress.to_string() should match WhatsApp Web's createSignalLikeAddress format"
    );
}
