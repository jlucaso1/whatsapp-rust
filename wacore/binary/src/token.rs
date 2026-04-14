pub const DICT_VERSION: u8 = 3;

// --- Public Constants for Special Tags ---
pub const LIST_EMPTY: u8 = 0;
pub const DICTIONARY_0: u8 = 236;
pub const DICTIONARY_1: u8 = 237;
pub const DICTIONARY_2: u8 = 238;
pub const DICTIONARY_3: u8 = 239;

pub const JID_PAIR: u8 = 250;
pub const HEX_8: u8 = 251;
pub const BINARY_8: u8 = 252;
pub const BINARY_20: u8 = 253;
pub const BINARY_32: u8 = 254;
pub const NIBBLE_8: u8 = 255;
pub const INTEROP_JID: u8 = 245;
pub const FB_JID: u8 = 246;
pub const AD_JID: u8 = 247;
pub const LIST_8: u8 = 248;
pub const LIST_16: u8 = 249;

pub const PACKED_MAX: u8 = 127;
pub const SINGLE_BYTE_MAX: u16 = 256;

/// Result of a unified token lookup — single hash for both token types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Single(u8),
    Double(u8, u8),
}

// Include the generated maps from the build script
include!(concat!(env!("OUT_DIR"), "/token_maps.rs"));

/// Look up a string in the unified token map (single PHF lookup).
pub fn index_of_token(token: &str) -> Option<TokenKind> {
    TOKEN_MAP.get(token).copied()
}

pub fn get_single_token(index: u8) -> Option<&'static str> {
    SINGLE_BYTE_TOKENS.get(index as usize).copied()
}

pub fn get_double_token(dict: u8, index: u8) -> Option<&'static str> {
    DOUBLE_BYTE_TOKENS
        .get(dict as usize)
        .and_then(|d| d.get(index as usize))
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test single byte token lookup round trip via unified map
    #[test]
    fn test_single_byte_token_roundtrip() {
        for i in 1u8..=235 {
            if let Some(token) = get_single_token(i) {
                let result = index_of_token(token);
                assert!(
                    matches!(result, Some(TokenKind::Single(idx)) if idx == i),
                    "Token '{}' at index {} doesn't round-trip",
                    token,
                    i,
                );
            }
        }
    }

    /// Test double byte token lookup round trip via unified map
    #[test]
    fn test_double_byte_token_roundtrip() {
        for dict in 0..4u8 {
            for idx in 0..255u8 {
                if let Some(token) = get_double_token(dict, idx) {
                    let result = index_of_token(token);
                    assert!(
                        matches!(result, Some(TokenKind::Double(d, i)) if d == dict && i == idx),
                        "Token '{}' at dict {} index {} doesn't round-trip",
                        token,
                        dict,
                        idx,
                    );
                }
            }
        }
    }

    /// Test that unknown strings return None for token lookups
    #[test]
    fn test_unknown_string_returns_none() {
        assert!(index_of_token("xyzzy_not_a_token_12345").is_none());
    }

    /// Test boundary token indices
    #[test]
    fn test_token_boundary_indices() {
        let token_0 = get_single_token(0);
        assert_eq!(token_0, Some(""), "Index 0 should be empty string token");

        assert!(get_single_token(LIST_8).is_none());
        assert!(get_single_token(LIST_16).is_none());
        assert!(get_single_token(JID_PAIR).is_none());
        assert!(get_single_token(HEX_8).is_none());
        assert!(get_single_token(BINARY_8).is_none());
        assert!(get_single_token(BINARY_20).is_none());
        assert!(get_single_token(BINARY_32).is_none());
        assert!(get_single_token(NIBBLE_8).is_none());
    }

    /// Test strings that almost match tokens but shouldn't be encoded as such
    #[test]
    fn test_almost_matching_strings() {
        if let Some(token) = get_single_token(1) {
            let modified = format!("{}_modified", token);
            assert!(index_of_token(&modified).is_none());

            let prefixed = format!("prefix_{}", token);
            assert!(index_of_token(&prefixed).is_none());

            let suffixed = format!("{}!", token);
            assert!(index_of_token(&suffixed).is_none());
        }
    }

    /// Test out of bounds dictionary lookup
    #[test]
    fn test_out_of_bounds_dictionary() {
        assert!(get_double_token(4, 0).is_none());
        assert!(get_double_token(5, 100).is_none());
        assert!(get_double_token(255, 0).is_none());
    }
}
