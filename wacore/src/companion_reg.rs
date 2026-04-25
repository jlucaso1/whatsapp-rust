//! Companion registration client type used by both pairing flows.
//! Mirrors `WAWebCompanionRegClientUtils.DEVICE_PLATFORM`
//! (`docs/captured-js/WAWeb/Link/DeviceQrcode.react.js`,
//! `Companion/RegClientUtils.js`, `Alt/DeviceLinkingIq.js`).

use waproto::whatsapp as wa;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, crate::WireEnum)]
#[wire(kind = "int")]
pub enum CompanionWebClientType {
    #[default]
    #[wire = 0]
    Unknown,
    #[wire = 1]
    Chrome,
    #[wire = 2]
    Edge,
    #[wire = 3]
    Firefox,
    #[wire = 4]
    Ie,
    #[wire = 5]
    Opera,
    #[wire = 6]
    Safari,
    #[wire = 7]
    Electron,
    #[wire = 8]
    Uwp,
    #[wire = 9]
    OtherWebClient,
    /// Forward-compat for wire integers WA Web hasn't shipped yet.
    /// Never produced by `companion_web_client_type_for_*`; only constructed
    /// via `From<i32>` when decoding an unrecognised value.
    #[wire_fallback]
    Unrecognized(i32),
}

impl std::fmt::Display for CompanionWebClientType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.code().fmt(f)
    }
}

/// Browser name suitable for `companion_platform_display`. Server validates
/// this field and rejects anything outside the 6 real browsers, so non-browser
/// variants fall back to "Chrome" — what WA Web's `info().name` would emit
/// even from Electron contexts (Electron's userAgent reports "Chrome").
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
        | CompanionWebClientType::Unrecognized(_) => "Chrome",
    }
}

pub fn companion_web_client_type_for_platform(
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
        P::Ipad
        | P::AndroidTablet
        | P::Ohana
        | P::Aloha
        | P::Catalina
        | P::TclTv
        | P::IosPhone
        | P::IosCatalyst
        | P::AndroidPhone
        | P::AndroidAmbiguous
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

/// Builds the `companion_platform_display` string. WA Web sends
/// `<browser_name> (<os>)` where `browser_name` is one of 6 valid browsers and
/// `os` is non-empty; the server validates and 400s on anything else.
///
/// Empty/whitespace OS falls back to "Linux" since WA Web never sends bare
/// browser names — keeping the parenthesised OS slot is required.
pub fn companion_platform_display(ct: CompanionWebClientType, os: &str) -> String {
    let os = os.trim();
    let os = if os.is_empty() { "Linux" } else { os };
    format!("{} ({})", companion_browser_name(ct), os)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_codes_match_wa_web() {
        assert_eq!(CompanionWebClientType::Unknown.code(), 0);
        assert_eq!(CompanionWebClientType::Chrome.code(), 1);
        assert_eq!(CompanionWebClientType::Edge.code(), 2);
        assert_eq!(CompanionWebClientType::Firefox.code(), 3);
        assert_eq!(CompanionWebClientType::Ie.code(), 4);
        assert_eq!(CompanionWebClientType::Opera.code(), 5);
        assert_eq!(CompanionWebClientType::Safari.code(), 6);
        assert_eq!(CompanionWebClientType::Electron.code(), 7);
        assert_eq!(CompanionWebClientType::Uwp.code(), 8);
        assert_eq!(CompanionWebClientType::OtherWebClient.code(), 9);
    }

    #[test]
    fn from_i32_round_trips_known_values() {
        for ct in [
            CompanionWebClientType::Unknown,
            CompanionWebClientType::Chrome,
            CompanionWebClientType::Edge,
            CompanionWebClientType::Firefox,
            CompanionWebClientType::Ie,
            CompanionWebClientType::Opera,
            CompanionWebClientType::Safari,
            CompanionWebClientType::Electron,
            CompanionWebClientType::Uwp,
            CompanionWebClientType::OtherWebClient,
        ] {
            assert_eq!(CompanionWebClientType::from(ct.code()), ct);
        }
    }

    #[test]
    fn from_i32_unknown_value_uses_unrecognized_fallback() {
        let ct = CompanionWebClientType::from(42);
        assert_eq!(ct, CompanionWebClientType::Unrecognized(42));
        assert_eq!(ct.code(), 42);
        let ct = CompanionWebClientType::from(-1);
        assert_eq!(ct, CompanionWebClientType::Unrecognized(-1));
    }

    #[test]
    fn default_is_unknown_zero() {
        assert_eq!(
            CompanionWebClientType::default(),
            CompanionWebClientType::Unknown,
        );
        assert_eq!(CompanionWebClientType::default().code(), 0);
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
    fn mobile_and_xr_collapse_to_other() {
        use CompanionWebClientType as C;
        use wa::device_props::PlatformType as P;
        for pt in [
            P::Ipad,
            P::AndroidPhone,
            P::AndroidTablet,
            P::IosPhone,
            P::IosCatalyst,
            P::AndroidAmbiguous,
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
            CompanionWebClientType::Unrecognized(42),
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
