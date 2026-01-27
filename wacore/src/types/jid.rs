use crate::libsignal::protocol::ProtocolAddress;
use wacore_binary::jid::{Jid, JidExt as BinaryJidExt};

pub trait JidExt {
    fn to_protocol_address(&self) -> ProtocolAddress;

    /// Returns the Signal address string in WhatsApp Web format.
    /// Format: `{user}[:device]@{server}`
    /// - Device part `:device` only included when `device != 0`
    /// - Examples: `123456789@lid`, `123456789:33@lid`, `5511999887766@c.us`
    fn to_signal_address_string(&self) -> String;

    /// Converts this JID to a device JID by appending a device suffix to the server.
    ///
    /// Device JIDs are used for retry receipts and other protocol messages where the
    /// target is a specific device rather than a user. The device suffix is appended
    /// to the SERVER part (not the user part).
    ///
    /// # Format
    /// - Input:  `user[:agent]@server`
    /// - Output: `user[:agent]@server.<device>`
    ///
    /// # Examples
    /// - `123456@lid` → `123456@lid.0`
    /// - `123456:4@lid` → `123456:4@lid.0`
    /// - `123456@s.whatsapp.net` → `123456@s.whatsapp.net.0`
    /// - `123456@c.us.0` → `123456@c.us.0` (already has suffix, unchanged)
    ///
    /// # Implementation Notes
    /// This matches WhatsApp Web's `DEVICE_JID()` function from WAWebCommsWapMd:
    /// ```javascript
    /// // Appends device ID to server: "lid" → "lid.0", "c.us" → "c.us.0"
    /// ```
    ///
    /// The function detects existing device suffixes by checking if the server ends
    /// with `.<digits>`, and only appends `.0` if not already present.
    fn to_device_jid(&self) -> String;
}

impl JidExt for Jid {
    fn to_signal_address_string(&self) -> String {
        // WhatsApp Web's SignalAddress.toString() format:
        // - Device part `:device` only included when device != 0
        // - Full format: {user}[:device]@{server}
        //
        // From WAWebSignalAddress module:
        // ```javascript
        // toString=function(){
        //   var t=this.wid.device!=null&&this.wid.device!==0?":"+this.wid.device:"";
        //   // ...
        //   return [i.user,t,"@lid"].join("")
        // }
        // ```
        let device_part = if self.device != 0 {
            format!(":{}", self.device)
        } else {
            String::new()
        };

        // Map server names to WhatsApp Web's internal format
        // WhatsApp Web uses @c.us for phone numbers, @lid for LID
        let server = match self.server.as_str() {
            "s.whatsapp.net" => "c.us",
            other => other,
        };

        format!("{}{device_part}@{server}", self.user)
    }

    fn to_protocol_address(&self) -> ProtocolAddress {
        // WhatsApp Web's createSignalLikeAddress format:
        // ```javascript
        // function g(e){
        //   var t=0,  // <-- always 0 for the device_id portion
        //   n=new(o("WAWebSignalAddress")).SignalAddress(e),
        //   r=n.toString();
        //   return r+"."+t  // Signal address + ".0"
        // }
        // ```
        //
        // The full session key format is: {SignalAddress.toString()}.0
        // Examples:
        // - 123456789@lid.0 (LID user, device 0)
        // - 123456789:33@lid.0 (LID user with device 33)
        // - 5511999887766@c.us.0 (Phone number, device 0)
        //
        // The device is encoded in the name, and device_id is always 0.
        let name = self.to_signal_address_string();
        ProtocolAddress::new(name, 0.into())
    }

    fn to_device_jid(&self) -> String {
        // Check if server already has a device suffix (e.g., "lid.0", "c.us.1")
        // Device suffix is defined as: .<digits> at the end of the server string
        let server_has_device_suffix = self
            .server()
            .rsplit_once('.')
            .map(|(_prefix, suffix): (&str, &str)| {
                suffix.chars().all(|c| c.is_ascii_digit())
            })
            .unwrap_or(false);

        if server_has_device_suffix {
            // Already has device suffix (e.g., "user@lid.0"), return as-is
            self.to_string()
        } else {
            // No device suffix, append .0 to server (e.g., "user@lid" → "user@lid.0")
            format!("{}.0", self)
        }
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
    fn test_to_device_jid_lid_no_device() {
        // LID without device suffix in server
        let jid = Jid::from_str("123456789@lid").expect("test JID should be valid");
        assert_eq!(jid.to_device_jid(), "123456789@lid.0");
    }

    #[test]
    fn test_to_device_jid_lid_with_device() {
        // LID with device in user part
        let jid = Jid::from_str("123456789:4@lid").expect("test JID should be valid");
        assert_eq!(jid.to_device_jid(), "123456789:4@lid.0");
    }

    #[test]
    fn test_to_device_jid_lid_already_has_suffix() {
        // LID with device suffix already present in server
        let jid = Jid::from_str("123456789:4@lid.0").expect("test JID should be valid");
        assert_eq!(jid.to_device_jid(), "123456789:4@lid.0");
    }

    #[test]
    fn test_to_device_jid_phone_number() {
        // Phone number JID
        let jid = Jid::from_str("5511999887766@s.whatsapp.net").expect("test JID should be valid");
        assert_eq!(jid.to_device_jid(), "5511999887766@s.whatsapp.net.0");
    }

    #[test]
    fn test_to_device_jid_phone_with_device() {
        // Phone number with device in user part
        let jid = Jid::from_str("5511999887766:2@s.whatsapp.net").expect("test JID should be valid");
        assert_eq!(jid.to_device_jid(), "5511999887766:2@s.whatsapp.net.0");
    }

    #[test]
    fn test_to_device_jid_complex_server() {
        // Server with multiple dots like "s.whatsapp.net"
        let jid = Jid::from_str("123456@s.whatsapp.net").expect("test JID should be valid");
        assert_eq!(jid.to_device_jid(), "123456@s.whatsapp.net.0");
    }

    #[test]
    fn test_to_device_jid_already_has_multi_digit_suffix() {
        // Device suffix with multiple digits
        let jid = Jid::from_str("123456@lid.123").expect("test JID should be valid");
        assert_eq!(jid.to_device_jid(), "123456@lid.123");
    }
}
