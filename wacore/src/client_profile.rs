//! Identity presented in the noise-handshake `ClientPayload.UserAgent`.
//! Independent of `DeviceProps`. Default is [`ClientProfile::web`].

use waproto::whatsapp as wa;

#[derive(Debug, Clone)]
pub struct ClientProfile {
    pub user_agent_platform: wa::client_payload::user_agent::Platform,
    pub device: String,
    pub os_version: String,
    pub manufacturer: String,
    pub include_web_info: bool,
}

impl Default for ClientProfile {
    fn default() -> Self {
        Self::web()
    }
}

impl ClientProfile {
    pub fn web() -> Self {
        Self {
            user_agent_platform: wa::client_payload::user_agent::Platform::Web,
            device: "Desktop".to_string(),
            os_version: "0.1.0".to_string(),
            manufacturer: String::new(),
            include_web_info: true,
        }
    }

    pub fn android(os_version: impl Into<String>) -> Self {
        Self {
            user_agent_platform: wa::client_payload::user_agent::Platform::Android,
            device: "Smartphone".to_string(),
            os_version: os_version.into(),
            manufacturer: String::new(),
            include_web_info: false,
        }
    }

    pub fn smb_android(os_version: impl Into<String>) -> Self {
        Self {
            user_agent_platform: wa::client_payload::user_agent::Platform::SmbAndroid,
            device: "Smartphone".to_string(),
            os_version: os_version.into(),
            manufacturer: String::new(),
            include_web_info: false,
        }
    }

    pub fn ios(os_version: impl Into<String>) -> Self {
        Self {
            user_agent_platform: wa::client_payload::user_agent::Platform::Ios,
            device: "iPhone".to_string(),
            os_version: os_version.into(),
            manufacturer: "Apple".to_string(),
            include_web_info: false,
        }
    }

    pub fn macos(os_version: impl Into<String>) -> Self {
        Self {
            user_agent_platform: wa::client_payload::user_agent::Platform::Macos,
            device: "Desktop".to_string(),
            os_version: os_version.into(),
            manufacturer: "Apple".to_string(),
            include_web_info: false,
        }
    }

    pub fn windows(os_version: impl Into<String>) -> Self {
        Self {
            user_agent_platform: wa::client_payload::user_agent::Platform::Windows,
            device: "Desktop".to_string(),
            os_version: os_version.into(),
            manufacturer: String::new(),
            include_web_info: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_profile_matches_legacy_defaults() {
        let p = ClientProfile::web();
        assert_eq!(
            p.user_agent_platform,
            wa::client_payload::user_agent::Platform::Web
        );
        assert_eq!(p.device, "Desktop");
        assert_eq!(p.os_version, "0.1.0");
        assert_eq!(p.manufacturer, "");
        assert!(p.include_web_info);
    }

    #[test]
    fn android_profile_omits_web_info_and_carries_os_version() {
        let p = ClientProfile::android("13");
        assert_eq!(
            p.user_agent_platform,
            wa::client_payload::user_agent::Platform::Android
        );
        assert_eq!(p.os_version, "13");
        assert!(!p.include_web_info);
    }

    #[test]
    fn smb_android_uses_smb_platform() {
        let p = ClientProfile::smb_android("14");
        assert_eq!(
            p.user_agent_platform,
            wa::client_payload::user_agent::Platform::SmbAndroid
        );
        assert!(!p.include_web_info);
    }

    #[test]
    fn ios_profile_marks_apple_manufacturer() {
        let p = ClientProfile::ios("17.4");
        assert_eq!(
            p.user_agent_platform,
            wa::client_payload::user_agent::Platform::Ios
        );
        assert_eq!(p.manufacturer, "Apple");
        assert!(!p.include_web_info);
    }

    #[test]
    fn native_profiles_all_drop_web_info() {
        for p in [
            ClientProfile::android(""),
            ClientProfile::smb_android(""),
            ClientProfile::ios(""),
            ClientProfile::macos(""),
            ClientProfile::windows(""),
        ] {
            assert!(!p.include_web_info, "{:?} must omit web_info", p);
        }
    }
}
