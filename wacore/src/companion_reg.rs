//! Companion registration client type carried by the pairing QR string.
//! Mirrors `WAWebCompanionRegClientUtils.DEVICE_PLATFORM`
//! (`docs/captured-js/WAWeb/Link/DeviceQrcode.react.js`, `Companion/RegClientUtils.js`).

use std::fmt;

use waproto::whatsapp as wa;

/// Web-client type for the pairing QR. Discriminants are the wire integers,
/// so [`Self::code`] is a zero-cost cast.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CompanionWebClientType {
    #[default]
    Unknown = 0,
    Chrome = 1,
    Edge = 2,
    Firefox = 3,
    Ie = 4,
    Opera = 5,
    Safari = 6,
    Electron = 7,
    Uwp = 8,
    OtherWebClient = 9,
}

impl CompanionWebClientType {
    pub const fn code(self) -> i32 {
        self as i32
    }
}

impl fmt::Display for CompanionWebClientType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.code().fmt(f)
    }
}

/// Maps `DeviceProps.PlatformType` to the QR pairing enum. Non-web platforms
/// fall through to `OtherWebClient`, matching WA Web's fall-through for
/// unrecognised `WAWebMiscBrowserUtils.info().name`.
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

/// Missing or out-of-range `platform_type` decays to `Unknown` so the QR flow
/// never fails on DeviceProps shape.
pub fn companion_web_client_type_for_props(props: &wa::DeviceProps) -> CompanionWebClientType {
    props
        .platform_type
        .and_then(|v| wa::device_props::PlatformType::try_from(v).ok())
        .map(companion_web_client_type_for_platform)
        .unwrap_or_default()
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
}
