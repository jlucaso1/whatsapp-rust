use crate::libsignal::protocol::ProtocolAddress;
use wacore_binary::jid::Jid;

pub trait JidExt {
    fn to_protocol_address(&self) -> ProtocolAddress;

    /// Returns the Signal address string in WhatsApp Web format.
    /// Format: `{user}[:device]@{server}`
    /// - Device part `:device` only included when `device != 0`
    /// - Examples: `123456789@lid`, `123456789:33@lid`, `5511999887766@c.us`
    fn to_signal_address_string(&self) -> String;

    /// Returns the full protocol address string including the device_id suffix.
    /// Format: `{signal_address_string}.0`
    /// This is equivalent to `to_protocol_address().to_string()` but avoids
    /// the intermediate ProtocolAddress allocation — one String instead of two.
    fn to_protocol_address_string(&self) -> String;
}

impl JidExt for Jid {
    fn to_signal_address_string(&self) -> String {
        use std::fmt::Write;

        // Map server names to WhatsApp Web's internal format
        // WhatsApp Web uses @c.us for phone numbers, @lid for LID
        let server = match &*self.server {
            "s.whatsapp.net" => "c.us",
            other => other,
        };

        // Pre-size the output: user + ":" + device(max 5 digits) + "@" + server
        let mut result = String::with_capacity(self.user.len() + 7 + server.len());
        result.push_str(&self.user);
        if self.device != 0 {
            result.push(':');
            let _ = write!(result, "{}", self.device);
        }
        result.push('@');
        result.push_str(server);
        result
    }

    fn to_protocol_address(&self) -> ProtocolAddress {
        let name = self.to_signal_address_string();
        ProtocolAddress::new(name, 0.into())
    }

    fn to_protocol_address_string(&self) -> String {
        use std::fmt::Write;

        let server = match &*self.server {
            "s.whatsapp.net" => "c.us",
            other => other,
        };

        // Pre-size: user + ":" + device(max 5) + "@" + server + ".0"
        let mut result = String::with_capacity(self.user.len() + 9 + server.len());
        result.push_str(&self.user);
        if self.device != 0 {
            result.push(':');
            let _ = write!(result, "{}", self.device);
        }
        result.push('@');
        result.push_str(server);
        result.push_str(".0");
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_signal_address_string_lid_no_device() {
        let jid = Jid::from_str("123456789@lid").expect("test JID should be valid");
        assert_eq!(jid.to_signal_address_string(), "123456789@lid");
    }

    #[test]
    fn test_signal_address_string_lid_with_device() {
        let jid = Jid::from_str("123456789:33@lid").expect("test JID should be valid");
        assert_eq!(jid.to_signal_address_string(), "123456789:33@lid");
    }

    #[test]
    fn test_signal_address_string_lid_with_dot_in_user() {
        // LID user IDs can contain dots that are part of the identity
        let jid = Jid::from_str("100000000000001.1:75@lid").expect("test JID should be valid");
        assert_eq!(jid.to_signal_address_string(), "100000000000001.1:75@lid");
    }

    #[test]
    fn test_signal_address_string_phone_number() {
        // s.whatsapp.net should be converted to c.us
        let jid = Jid::from_str("5511999887766@s.whatsapp.net").expect("test JID should be valid");
        assert_eq!(jid.to_signal_address_string(), "5511999887766@c.us");
    }

    #[test]
    fn test_signal_address_string_phone_with_device() {
        let jid =
            Jid::from_str("5511999887766:33@s.whatsapp.net").expect("test JID should be valid");
        assert_eq!(jid.to_signal_address_string(), "5511999887766:33@c.us");
    }

    #[test]
    fn test_protocol_address_format() {
        // ProtocolAddress.to_string() should produce: {name}.{device_id}
        // Which matches WhatsApp Web's createSignalLikeAddress format
        let jid = Jid::from_str("123456789:33@lid").expect("test JID should be valid");
        let addr = jid.to_protocol_address();

        assert_eq!(addr.name(), "123456789:33@lid");
        assert_eq!(u32::from(addr.device_id()), 0);
        assert_eq!(addr.to_string(), "123456789:33@lid.0");
    }

    #[test]
    fn test_protocol_address_lid_with_dot() {
        let jid = Jid::from_str("100000000000001.1:75@lid").expect("test JID should be valid");
        let addr = jid.to_protocol_address();

        assert_eq!(addr.name(), "100000000000001.1:75@lid");
        assert_eq!(u32::from(addr.device_id()), 0);
        assert_eq!(addr.to_string(), "100000000000001.1:75@lid.0");
    }

    #[test]
    fn test_protocol_address_phone_number() {
        let jid = Jid::from_str("5511999887766@s.whatsapp.net").expect("test JID should be valid");
        let addr = jid.to_protocol_address();

        assert_eq!(addr.name(), "5511999887766@c.us");
        assert_eq!(u32::from(addr.device_id()), 0);
        assert_eq!(addr.to_string(), "5511999887766@c.us.0");
    }

    #[test]
    fn test_protocol_address_string_matches_to_string() {
        // to_protocol_address_string() must produce the same output as
        // to_protocol_address().to_string() for all JID types.
        let jids = [
            "123456789@lid",
            "123456789:33@lid",
            "100000000000001.1:75@lid",
            "5511999887766@s.whatsapp.net",
            "5511999887766:33@s.whatsapp.net",
        ];
        for jid_str in &jids {
            let jid = Jid::from_str(jid_str).expect("test JID should be valid");
            assert_eq!(
                jid.to_protocol_address_string(),
                jid.to_protocol_address().to_string(),
                "mismatch for JID: {jid_str}"
            );
        }
    }
}
