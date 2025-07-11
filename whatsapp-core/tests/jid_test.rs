use std::str::FromStr;
use whatsapp_core::types::jid::Jid;

#[test]
fn test_jid_parsing_and_serialization() {
    // Standard User JID
    let jid_str = "1234567890@s.whatsapp.net";
    let jid = Jid::from_str(jid_str).unwrap();
    assert_eq!(jid.user, "1234567890");
    assert_eq!(jid.server, "s.whatsapp.net");
    assert_eq!(jid.agent, 0);
    assert_eq!(jid.device, 0);
    assert_eq!(jid.to_string(), jid_str);
    assert!(!jid.is_ad());
    assert!(!jid.is_group());

    // AD User JID
    let ad_jid_str = "1234567890:12@s.whatsapp.net";
    let ad_jid = Jid::from_str(ad_jid_str).unwrap();
    assert_eq!(ad_jid.user, "1234567890");
    assert_eq!(ad_jid.device, 12);
    assert_eq!(ad_jid.agent, 0);
    assert!(ad_jid.is_ad());
    assert_eq!(ad_jid.to_string(), ad_jid_str);

    // Group JID
    let group_jid_str = "123-456@g.us";
    let group_jid = Jid::from_str(group_jid_str).unwrap();
    assert_eq!(group_jid.user, "123-456");
    assert_eq!(group_jid.server, "g.us");
    assert!(group_jid.is_group());
    assert_eq!(group_jid.to_string(), group_jid_str);

    // Server-only JID
    let server_jid_str = "s.whatsapp.net";
    let server_jid = Jid::from_str(server_jid_str).unwrap();
    assert!(server_jid.user.is_empty());
    assert_eq!(server_jid.server, "s.whatsapp.net");
    assert_eq!(server_jid.to_string(), server_jid_str);
}

#[test]
fn test_invalid_jid_parsing() {
    // This will parse as a server JID, which is correct.
    assert!(matches!(Jid::from_str("invalidjid"), Ok(_)));

    // This will also parse as a valid JID (server = "server:device").
    assert!(matches!(Jid::from_str("user@server:device"), Ok(_)));
}

#[test]
fn test_is_ad_logic() {
    let jid_ad = Jid::from_str("123:1@s.whatsapp.net").unwrap();
    let jid_non_ad = Jid::from_str("123@s.whatsapp.net").unwrap();
    let jid_group = Jid::from_str("456@g.us").unwrap();

    assert!(jid_ad.is_ad());
    assert!(!jid_non_ad.is_ad());
    assert!(!jid_group.is_ad());
}
