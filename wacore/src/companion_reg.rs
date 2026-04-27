//! `companion_platform_id` + `companion_platform_display` emission.
//! Encoding only.

use waproto::whatsapp as wa;

/// Prefix `WAWebLinkDeviceQrcode` uses when iOS native-camera linking is on.
/// Concatenate with `make_qr_data` output to get a scannable deep-link URL.
pub const NATIVE_CAMERA_DEEP_LINK_PREFIX: &str = "https://wa.me/settings/linked_devices#";

/// Web codes follow `WAWebCompanionRegClientUtils.DEVICE_PLATFORM`.
/// Android letters need server-side attestation, so they're reachable
/// only through explicit opt-in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum CompanionWebClientType {
    Chrome,
    Edge,
    Firefox,
    Ie,
    Opera,
    Safari,
    Electron,
    Uwp,
    /// Default fallback. The proto's `UNKNOWN` (wire `'0'`) is absent
    /// because WA Web never emits it from a real browser and the server
    /// rejects it.
    #[default]
    OtherWebClient,
    AndroidTablet,
    AndroidPhone,
    AndroidAmbiguous,
}

impl CompanionWebClientType {
    /// Single-byte ASCII id placed in `<companion_platform_id>`.
    pub const fn wire_byte(self) -> u8 {
        match self {
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
        CompanionWebClientType::Electron
        | CompanionWebClientType::Uwp
        | CompanionWebClientType::OtherWebClient
        | CompanionWebClientType::AndroidTablet
        | CompanionWebClientType::AndroidPhone
        | CompanionWebClientType::AndroidAmbiguous => "Chrome",
    }
}

/// Android maps to `Chrome` because that's what real WA Web on
/// Chrome-Android emits and what the server accepts; the Android
/// letters need attestation we can't fake from this crate, so they
/// stay behind `PairCodeOptions::platform_id`. iOS/AR/VR and the
/// proto's `UNKNOWN` collapse to `OtherWebClient` — `'0'` would be
/// server-rejected.
pub const fn companion_web_client_type_for_platform(
    pt: wa::device_props::PlatformType,
) -> CompanionWebClientType {
    use CompanionWebClientType as C;
    use wa::device_props::PlatformType as P;
    match pt {
        P::Chrome => C::Chrome,
        P::Firefox => C::Firefox,
        P::Ie => C::Ie,
        P::Opera => C::Opera,
        P::Safari => C::Safari,
        P::Edge => C::Edge,
        P::Desktop => C::Electron,
        P::Uwp => C::Uwp,
        P::AndroidPhone | P::AndroidTablet | P::AndroidAmbiguous => C::Chrome,
        P::Unknown
        | P::Ipad
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
        .unwrap_or(CompanionWebClientType::OtherWebClient)
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
        assert_eq!(format!("{}", CompanionWebClientType::Chrome), "1");
        assert_eq!(format!("{}", CompanionWebClientType::OtherWebClient), "9");
        assert_eq!(format!("{}", CompanionWebClientType::AndroidPhone), "e");
        assert_eq!(format!("{}", CompanionWebClientType::AndroidTablet), "d");
        assert_eq!(format!("{}", CompanionWebClientType::AndroidAmbiguous), "f");
    }

    #[test]
    fn default_is_other_web_client_nine() {
        assert_eq!(
            CompanionWebClientType::default(),
            CompanionWebClientType::OtherWebClient,
        );
        assert_eq!(CompanionWebClientType::default().wire_byte(), b'9');
    }

    #[test]
    fn browser_and_desktop_platform_types_map_to_their_variants() {
        use CompanionWebClientType as C;
        use wa::device_props::PlatformType as P;
        for (pt, expected) in [
            (P::Chrome, C::Chrome),
            (P::Firefox, C::Firefox),
            (P::Edge, C::Edge),
            (P::Safari, C::Safari),
            (P::Opera, C::Opera),
            (P::Ie, C::Ie),
            (P::Desktop, C::Electron),
            (P::Uwp, C::Uwp),
        ] {
            assert_eq!(
                companion_web_client_type_for_platform(pt),
                expected,
                "{pt:?}"
            );
        }
    }

    #[test]
    fn android_platform_types_map_to_chrome() {
        use CompanionWebClientType as C;
        use wa::device_props::PlatformType as P;
        for pt in [P::AndroidPhone, P::AndroidTablet, P::AndroidAmbiguous] {
            assert_eq!(
                companion_web_client_type_for_platform(pt),
                C::Chrome,
                "{pt:?}"
            );
        }
    }

    #[test]
    fn unconfirmed_platform_types_collapse_to_other() {
        use CompanionWebClientType as C;
        use wa::device_props::PlatformType as P;
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
                "{pt:?}",
            );
        }
    }

    #[test]
    fn proto_unknown_collapses_to_other_web_client() {
        use CompanionWebClientType as C;
        use wa::device_props::PlatformType as P;
        assert_eq!(
            companion_web_client_type_for_platform(P::Unknown),
            C::OtherWebClient,
        );
    }

    #[test]
    fn android_variants_still_emit_their_wire_bytes_when_used_directly() {
        assert_eq!(CompanionWebClientType::AndroidPhone.wire_byte(), b'e');
        assert_eq!(CompanionWebClientType::AndroidTablet.wire_byte(), b'd');
        assert_eq!(CompanionWebClientType::AndroidAmbiguous.wire_byte(), b'f');
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
    fn for_props_missing_platform_type_is_other_web_client() {
        let props = wa::DeviceProps::default();
        assert_eq!(
            companion_web_client_type_for_props(&props),
            CompanionWebClientType::OtherWebClient,
        );
    }

    #[test]
    fn for_props_invalid_platform_type_is_other_web_client() {
        let props = wa::DeviceProps {
            platform_type: Some(9999),
            ..Default::default()
        };
        assert_eq!(
            companion_web_client_type_for_props(&props),
            CompanionWebClientType::OtherWebClient,
        );
    }

    #[test]
    fn browser_name_for_six_valid_browsers() {
        use CompanionWebClientType as C;
        for (ct, name) in [
            (C::Chrome, "Chrome"),
            (C::Edge, "Edge"),
            (C::Firefox, "Firefox"),
            (C::Ie, "IE"),
            (C::Opera, "Opera"),
            (C::Safari, "Safari"),
        ] {
            assert_eq!(companion_browser_name(ct), name, "{ct:?}");
        }
    }

    #[test]
    fn browser_name_for_non_browser_falls_back_to_chrome() {
        for ct in [
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
