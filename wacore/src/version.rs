const REVISION_KEY: &str = "client_revision";
const ASSETS_KEY: &str = "assets-manifest-";

/// Parses the WhatsApp Web version from sw.js content.
/// Returns `(2, 3000, revision)` tuple.
pub fn parse_sw_js(s: &str) -> Option<(u32, u32, u32)> {
    if let Some(start_index) = s.find(REVISION_KEY) {
        let suffix = &s[start_index + REVISION_KEY.len()..];

        if let Some(first_digit_index) = suffix.find(|c: char| c.is_ascii_digit()) {
            let number_slice = &suffix[first_digit_index..];

            let end_of_number_index = number_slice
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(number_slice.len());

            let version_str = &number_slice[..end_of_number_index];

            if let Ok(revision) = version_str.parse::<u32>() {
                return Some((2, 3000, revision));
            }
        }
    }

    if let Some(start_index) = s.find(ASSETS_KEY) {
        let suffix = &s[start_index + ASSETS_KEY.len()..];
        if let Some(end_index) = suffix.find(|c: char| !c.is_ascii_digit()) {
            let version_str = &suffix[..end_index];
            if !s.contains(&format!("wa{}.canary", version_str)) {
                return Some((2, 3000, 0));
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sw_js_client_revision_quoted() {
        let s = r#"var x = {"client_revision": "123456"};"#;
        assert_eq!(parse_sw_js(s), Some((2, 3000, 123456)));
    }

    #[test]
    fn test_parse_sw_js_client_revision_unquoted() {
        let s = r#"client_revision:12345;"#;
        assert_eq!(parse_sw_js(s), Some((2, 3000, 12345)));
    }

    #[test]
    fn test_parse_sw_js_assets_fallback() {
        let s = "... assets-manifest-98765 ...";
        assert_eq!(parse_sw_js(s), Some((2, 3000, 0)));
    }

    #[test]
    fn test_parse_sw_js_realistic_sw_js() {
        let s = r#"{"client_revision":1026131876}"#;
        assert_eq!(parse_sw_js(s), Some((2, 3000, 1026131876)));
    }

    #[test]
    fn test_parse_sw_js_not_found() {
        let s = "no version info here";
        assert_eq!(parse_sw_js(s), None);
    }
}
