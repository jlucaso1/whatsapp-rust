//! `companion_platform_id` and `companion_platform_display` emission.
//!
//! Server accepts 23 single-byte ids: digits `0..9` (WA Web) and letters
//! `a..m`. Only the 13 with a confirmed platform meaning are exposed.
//! Sources: WA Web `WAWebCompanionRegClientUtils` for the digits; the
//! official WhatsApp Android client for the mobile letters `d`, `e`,
//! `f`. Adding the rest without binary or wire confirmation risks
//! mislabelling the device on the primary side.

use waproto::whatsapp as wa;

/// Prefix `WAWebLinkDeviceQrcode` uses when iOS native-camera linking is on.
/// Concatenate with `make_qr_data` output to get a scannable deep-link URL.
pub const NATIVE_CAMERA_DEEP_LINK_PREFIX: &str = "https://wa.me/settings/linked_devices#";

/// Encode-only: every variant has a fixed single-byte ASCII wire form.
/// Decoding from the wire is not modelled because this crate only emits
/// the field, never receives it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum CompanionWebClientType {
    // Web (digit codes from WAWebCompanionRegClientUtils.DEVICE_PLATFORM).
    #[default]
    Unknown,
    Chrome,
    Edge,
    Firefox,
    Ie,
    Opera,
    Safari,
    Electron,
    Uwp,
    OtherWebClient,
    // Mobile (letter codes from the official WhatsApp Android client).
    AndroidTablet,
    AndroidPhone,
    AndroidAmbiguous,
}

impl CompanionWebClientType {
    /// Single-byte ASCII id placed in `<companion_platform_id>`.
    pub const fn wire_byte(self) -> u8 {
        match self {
            Self::Unknown => b'0',
            Self::Chrome => b'1',
            Self::Edge => b'2',
            Self::Firefox => b'3',
            Self::Ie => b'4',
            Self::Opera => b'5',
            Self::Safari => b'6',
            Self::Electron => b'7',
            Self::Uwp => b'8',
            Self::OtherWebClient => b'9',
            Self::AndroidTablet => b'd',
            Self::AndroidPhone => b'e',
            Self::AndroidAmbiguous => b'f',
        }
    }
}

impl std::fmt::Display for CompanionWebClientType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.wire_byte() as char)
    }
}

/// Browser label for `companion_platform_display`. Non-browser variants
/// fall back to "Chrome" because WA Web's `info().name` reports the
/// underlying Chromium renderer in those contexts. Mobile variants are
/// short-circuited by [`companion_platform_display`] before reaching here.
pub const fn companion_browser_name(ct: CompanionWebClientType) -> &'static str {
    match ct {
        CompanionWebClientType::Chrome => "Chrome",
        CompanionWebClientType::Edge => "Edge",
        CompanionWebClientType::Firefox => "Firefox",
        CompanionWebClientType::Ie => "IE",
        CompanionWebClientType::Opera => "Opera",
        CompanionWebClientType::Safari => "Safari",
        CompanionWebClientType::Unknown
        | CompanionWebClientType::Electron
        | CompanionWebClientType::Uwp
        | CompanionWebClientType::OtherWebClient
        | CompanionWebClientType::AndroidTablet
        | CompanionWebClientType::AndroidPhone
        | CompanionWebClientType::AndroidAmbiguous => "Chrome",
    }
}

/// Maps `DeviceProps::PlatformType` to a wire variant. Variants without
/// a confirmed letter fall back to `OtherWebClient` ('9'), which the
/// server still accepts.
pub const fn companion_web_client_type_for_platform(
    pt: wa::device_props::PlatformType,
) -> CompanionWebClientType {
    use CompanionWebClientType as C;
    use wa::device_props::PlatformType as P;
    match pt {
        P::Unknown => C::Unknown,
        P::Chrome => C::Chrome,
        P::Firefox => C::Firefox,
        P::Ie => C::Ie,
        P::Opera => C::Opera,
        P::Safari => C::Safari,
        P::Edge => C::Edge,
        P::Desktop => C::Electron,
        P::Uwp => C::Uwp,
        P::AndroidPhone => C::AndroidPhone,
        P::AndroidTablet => C::AndroidTablet,
        P::AndroidAmbiguous => C::AndroidAmbiguous,
        P::Ipad
        | P::Ohana
        | P::Aloha
        | P::Catalina
        | P::TclTv
        | P::IosPhone
        | P::IosCatalyst
        | P::WearOs
        | P::ArWrist
        | P::ArDevice
        | P::Vr
        | P::CloudApi
        | P::Smartglasses => C::OtherWebClient,
    }
}

pub fn companion_web_client_type_for_props(props: &wa::DeviceProps) -> CompanionWebClientType {
    props
        .platform_type
        .and_then(|v| wa::device_props::PlatformType::try_from(v).ok())
        .map(companion_web_client_type_for_platform)
        .unwrap_or_default()
}

/// `companion_platform_display` body. Server validates only length
/// 1..=100; there is no browser whitelist. Web variants emit
/// `<Browser> (<OS>)`, mirroring `WAWebAltDeviceLinkingIq`; Android
/// variants emit `Android (<OS>)`, matching the official Android client.
/// Empty OS substitutes `Linux`.
pub fn companion_platform_display(ct: CompanionWebClientType, os: &str) -> String {
    use CompanionWebClientType as C;
    let os = os.trim();
    let os = if os.is_empty() { "Linux" } else { os };
    match ct {
        C::AndroidPhone | C::AndroidTablet | C::AndroidAmbiguous => {
            format!("Android ({os})")
        }
        _ => format!("{} ({})", companion_browser_name(ct), os),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_byte_matches_wa_web() {
        assert_eq!(CompanionWebClientType::Unknown.wire_byte(), b'0');
        assert_eq!(CompanionWebClientType::Chrome.wire_byte(), b'1');
        assert_eq!(CompanionWebClientType::Edge.wire_byte(), b'2');
        assert_eq!(CompanionWebClientType::Firefox.wire_byte(), b'3');
        assert_eq!(CompanionWebClientType::Ie.wire_byte(), b'4');
        assert_eq!(CompanionWebClientType::Opera.wire_byte(), b'5');
        assert_eq!(CompanionWebClientType::Safari.wire_byte(), b'6');
        assert_eq!(CompanionWebClientType::Electron.wire_byte(), b'7');
        assert_eq!(CompanionWebClientType::Uwp.wire_byte(), b'8');
        assert_eq!(CompanionWebClientType::OtherWebClient.wire_byte(), b'9');
    }

    #[test]
    fn wire_byte_matches_apk_for_mobile() {
        assert_eq!(CompanionWebClientType::AndroidTablet.wire_byte(), b'd');
        assert_eq!(CompanionWebClientType::AndroidPhone.wire_byte(), b'e');
        assert_eq!(CompanionWebClientType::AndroidAmbiguous.wire_byte(), b'f');
    }

    #[test]
    fn display_renders_wire_byte_as_char() {
        assert_eq!(format!("{}", CompanionWebClientType::Unknown), "0");
        assert_eq!(format!("{}", CompanionWebClientType::Chrome), "1");
        assert_eq!(format!("{}", CompanionWebClientType::OtherWebClient), "9");
        assert_eq!(format!("{}", CompanionWebClientType::AndroidPhone), "e");
        assert_eq!(format!("{}", CompanionWebClientType::AndroidTablet), "d");
        assert_eq!(format!("{}", CompanionWebClientType::AndroidAmbiguous), "f");
    }

    #[test]
    fn default_is_unknown_zero() {
        assert_eq!(
            CompanionWebClientType::default(),
            CompanionWebClientType::Unknown,
        );
        assert_eq!(CompanionWebClientType::default().wire_byte(), b'0');
    }

    #[test]
    fn browser_platform_types_round_trip() {
        use CompanionWebClientType as C;
        use wa::device_props::PlatformType as P;
        assert_eq!(companion_web_client_type_for_platform(P::Chrome), C::Chrome);
        assert_eq!(
            companion_web_client_type_for_platform(P::Firefox),
            C::Firefox
        );
        assert_eq!(companion_web_client_type_for_platform(P::Edge), C::Edge);
        assert_eq!(companion_web_client_type_for_platform(P::Safari), C::Safari);
        assert_eq!(companion_web_client_type_for_platform(P::Opera), C::Opera);
        assert_eq!(companion_web_client_type_for_platform(P::Ie), C::Ie);
    }

    #[test]
    fn desktop_maps_to_electron_and_uwp_preserved() {
        use CompanionWebClientType as C;
        use wa::device_props::PlatformType as P;
        assert_eq!(
            companion_web_client_type_for_platform(P::Desktop),
            C::Electron
        );
        assert_eq!(companion_web_client_type_for_platform(P::Uwp), C::Uwp);
    }

    #[test]
    fn android_platform_types_map_to_dedicated_letters() {
        use CompanionWebClientType as C;
        use wa::device_props::PlatformType as P;
        assert_eq!(
            companion_web_client_type_for_platform(P::AndroidPhone),
            C::AndroidPhone,
        );
        assert_eq!(
            companion_web_client_type_for_platform(P::AndroidTablet),
            C::AndroidTablet,
        );
        assert_eq!(
            companion_web_client_type_for_platform(P::AndroidAmbiguous),
            C::AndroidAmbiguous,
        );
    }

    #[test]
    fn unconfirmed_platform_types_collapse_to_other() {
        use CompanionWebClientType as C;
        use wa::device_props::PlatformType as P;
        // No confirmed letter for these yet (would need iOS/Mac/Quest RE
        // or live capture). Fallback to OtherWebClient ('9') stays
        // server-valid.
        for pt in [
            P::Ipad,
            P::IosPhone,
            P::IosCatalyst,
            P::WearOs,
            P::ArWrist,
            P::ArDevice,
            P::Vr,
            P::Ohana,
            P::Aloha,
            P::Catalina,
            P::TclTv,
            P::CloudApi,
            P::Smartglasses,
        ] {
            assert_eq!(
                companion_web_client_type_for_platform(pt),
                C::OtherWebClient,
                "{pt:?} must fall back to OtherWebClient",
            );
        }
    }

    #[test]
    fn for_props_reads_platform_type() {
        let props = wa::DeviceProps {
            platform_type: Some(wa::device_props::PlatformType::Chrome as i32),
            ..Default::default()
        };
        assert_eq!(
            companion_web_client_type_for_props(&props),
            CompanionWebClientType::Chrome,
        );
    }

    #[test]
    fn for_props_missing_platform_type_is_unknown() {
        let props = wa::DeviceProps::default();
        assert_eq!(
            companion_web_client_type_for_props(&props),
            CompanionWebClientType::Unknown,
        );
    }

    #[test]
    fn for_props_invalid_platform_type_is_unknown() {
        let props = wa::DeviceProps {
            platform_type: Some(9999),
            ..Default::default()
        };
        assert_eq!(
            companion_web_client_type_for_props(&props),
            CompanionWebClientType::Unknown,
        );
    }

    #[test]
    fn browser_name_for_six_valid_browsers() {
        assert_eq!(
            companion_browser_name(CompanionWebClientType::Chrome),
            "Chrome"
        );
        assert_eq!(companion_browser_name(CompanionWebClientType::Edge), "Edge");
        assert_eq!(
            companion_browser_name(CompanionWebClientType::Firefox),
            "Firefox"
        );
        assert_eq!(companion_browser_name(CompanionWebClientType::Ie), "IE");
        assert_eq!(
            companion_browser_name(CompanionWebClientType::Opera),
            "Opera"
        );
        assert_eq!(
            companion_browser_name(CompanionWebClientType::Safari),
            "Safari"
        );
    }

    #[test]
    fn browser_name_for_non_browser_falls_back_to_chrome() {
        for ct in [
            CompanionWebClientType::Unknown,
            CompanionWebClientType::Electron,
            CompanionWebClientType::Uwp,
            CompanionWebClientType::OtherWebClient,
        ] {
            assert_eq!(companion_browser_name(ct), "Chrome", "{ct:?}");
        }
    }

    #[test]
    fn platform_display_always_browser_paren_os() {
        assert_eq!(
            companion_platform_display(CompanionWebClientType::Chrome, "Linux"),
            "Chrome (Linux)"
        );
        assert_eq!(
            companion_platform_display(CompanionWebClientType::Firefox, "Mac"),
            "Firefox (Mac)"
        );
    }

    #[test]
    fn platform_display_empty_os_defaults_to_linux() {
        assert_eq!(
            companion_platform_display(CompanionWebClientType::Chrome, ""),
            "Chrome (Linux)"
        );
        assert_eq!(
            companion_platform_display(CompanionWebClientType::Chrome, "   "),
            "Chrome (Linux)"
        );
    }

    #[test]
    fn platform_display_non_browser_uses_chrome() {
        assert_eq!(
            companion_platform_display(CompanionWebClientType::OtherWebClient, "Android"),
            "Chrome (Android)"
        );
        assert_eq!(
            companion_platform_display(CompanionWebClientType::Electron, "Mac"),
            "Chrome (Mac)"
        );
    }
}
