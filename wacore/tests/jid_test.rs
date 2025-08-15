use std::str::FromStr;
use wacore_binary::jid::{Jid, JidExt};

#[test]
fn test_jid_parsing_and_serialization() {
    let jid_str = "1234567890@s.whatsapp.net";
    let jid = Jid::from_str(jid_str).unwrap();
    assert_eq!(jid.user, "1234567890");
    assert_eq!(jid.server, "s.whatsapp.net");
    assert_eq!(jid.agent, 0);
    assert_eq!(jid.device, 0);
    assert_eq!(jid.to_string(), jid_str);
    assert!(!jid.is_ad());
    assert!(!jid.is_group());

    let ad_jid_str = "1234567890:12@s.whatsapp.net";
    let ad_jid = Jid::from_str(ad_jid_str).unwrap();
    assert_eq!(ad_jid.user, "1234567890");
    assert_eq!(ad_jid.device, 12);
    assert_eq!(ad_jid.agent, 0);
    assert!(ad_jid.is_ad());
    assert_eq!(ad_jid.to_string(), ad_jid_str);

    let group_jid_str = "123-456@g.us";
    let group_jid = Jid::from_str(group_jid_str).unwrap();
    assert_eq!(group_jid.user, "123-456");
    assert_eq!(group_jid.server, "g.us");
    assert!(group_jid.is_group());
    assert_eq!(group_jid.to_string(), group_jid_str);

    let server_jid_str = "s.whatsapp.net";
    let server_jid = Jid::from_str(server_jid_str).unwrap();
    assert!(server_jid.user.is_empty());
    assert_eq!(server_jid.server, "s.whatsapp.net");
    assert_eq!(server_jid.to_string(), server_jid_str);
}

#[test]
fn test_invalid_jid_parsing() {
    assert!(Jid::from_str("invalidjid").is_ok());

    assert!(Jid::from_str("user@server:device").is_ok());
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
