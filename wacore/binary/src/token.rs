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

// Include the generated maps from the build script
include!(concat!(env!("OUT_DIR"), "/token_maps.rs"));

// The lookup functions now use the compile-time maps
pub fn index_of_single_token(token: &str) -> Option<u8> {
    SINGLE_BYTE_MAP.get(token).copied()
}

pub fn index_of_double_byte_token(token: &str) -> Option<(u8, u8)> {
    DOUBLE_BYTE_MAP.get(token).copied()
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
