use crate::token::DICT_VERSION;

/// Noise XX pattern name, zero-padded to HASHLEN (32 bytes) per Noise § 5.2.
/// Used on the first connect / pairing where the client has no cached server
/// static key. Mirrors WA Web's `M` constant in `WAWebOpenChatSocket`.
pub const NOISE_PATTERN_XX: &str = "Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00";

/// Noise IK pattern name, zero-padded to HASHLEN (32 bytes).
/// Used on reconnect when the client has a valid cached `serverStaticPublic`
/// (from a previous XX handshake). Saves one round trip and ships a 0-RTT
/// payload. Mirrors WA Web's `w` constant.
pub const NOISE_PATTERN_IK: &str = "Noise_IK_25519_AESGCM_SHA256\x00\x00\x00\x00";

/// Noise XXfallback pattern name (36 bytes, hashed by Noise spec).
/// Used to recover gracefully when an in-flight IK handshake is rejected by
/// the server (server's static rotated, cached pub key is stale). The client
/// reuses the ephemeral it already sent in the IK ClientHello and processes
/// the server's XX-style ServerHello. Mirrors WA Web's `A` constant.
pub const NOISE_PATTERN_XXFALLBACK: &str = "Noise_XXfallback_25519_AESGCM_SHA256";

pub const WA_MAGIC_VALUE: u8 = 6;
pub const WA_CONN_HEADER: [u8; 4] = [b'W', b'A', WA_MAGIC_VALUE, DICT_VERSION];

#[cfg(test)]
mod pattern_length_tests {
    use super::*;

    #[test]
    fn xx_is_padded_to_hashlen() {
        assert_eq!(NOISE_PATTERN_XX.len(), 32);
    }

    #[test]
    fn ik_is_padded_to_hashlen() {
        assert_eq!(NOISE_PATTERN_IK.len(), 32);
    }

    #[test]
    fn xxfallback_is_unpadded_36_bytes() {
        // Longer than HASHLEN -> Noise spec hashes it; padding here would be
        // a correctness bug on the wire. Lock the length explicitly.
        assert_eq!(NOISE_PATTERN_XXFALLBACK.len(), 36);
    }
}
