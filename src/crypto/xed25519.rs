/// A Rust implementation of the XEd25519 signature scheme found in libraries like `whatsmeow`.
/// This scheme uses an X25519 keypair but produces Ed25519-compatible signatures.
pub mod xed25519 {
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use curve25519_dalek::montgomery::MontgomeryPoint;
    use curve25519_dalek::scalar::Scalar;
    use ed25519_dalek::hazmat::ExpandedSecretKey;
    use ed25519_dalek::Verifier;
    use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
    use sha2::{Digest, Sha512};

    // The diversifier from whatsmeow/ecc/SignCurve25519.go
    const DIVERSIFIER: [u8; 32] = [
        0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF,
    ];

    /// Signs a message using the XEd25519 scheme.
    pub fn sign(priv_seed: &[u8; 32], message: &[u8], random: &[u8; 64]) -> Signature {
        let signing_key = SigningKey::from_bytes(priv_seed);
        let expanded_secret = ExpandedSecretKey::from(signing_key.as_bytes());
        let public: VerifyingKey = signing_key.verifying_key();
        let public_bytes = public.as_bytes();

        let mut r_hasher = Sha512::new();
        r_hasher.update(&DIVERSIFIER);
        r_hasher.update(priv_seed);
        r_hasher.update(message);
        r_hasher.update(random);
        let r_hash: [u8; 64] = r_hasher.finalize().into();
        let r_scalar = Scalar::from_bytes_mod_order_wide(&r_hash);

        let r_point = (r_scalar * ED25519_BASEPOINT_POINT).compress();

        let mut h_hasher = Sha512::new();
        h_hasher.update(r_point.as_bytes());
        h_hasher.update(public_bytes);
        h_hasher.update(message);
        let h_hash: [u8; 64] = h_hasher.finalize().into();
        let h_scalar = Scalar::from_bytes_mod_order_wide(&h_hash);

        let s_scalar = h_scalar * expanded_secret.scalar + r_scalar;

        let mut signature_bytes = [0u8; 64];
        signature_bytes[..32].copy_from_slice(r_point.as_bytes());
        signature_bytes[32..].copy_from_slice(&s_scalar.to_bytes());

        signature_bytes[63] &= 0x7F; // Clear the sign bit first
        signature_bytes[63] |= public_bytes[31] & 0x80; // Set the sign bit

        Signature::from_slice(&signature_bytes).unwrap()
    }

    /// Verifies an XEd25519 signature using only the public API of curve25519-dalek.
    ///
    /// # Arguments
    /// * `x25519_pub` - The 32-byte X25519 (Montgomery) public key.
    /// * `message` - The message that was signed.
    /// * `signature` - The 64-byte signature to verify.
    ///
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise.
    pub fn verify(x25519_pub: &[u8; 32], message: &[u8], signature: &Signature) -> bool {
        // 1. Extract the high bit from the signature and create a "clean" signature
        //    by clearing that bit for the final verification step.
        let mut sig_bytes = signature.to_bytes();
        let sign_bit = (sig_bytes[63] & 0x80) >> 7;
        sig_bytes[63] &= 0x7F; // Clear the high bit

        // Attempt to create a new Signature object from the cleaned bytes.
        let Ok(cleaned_signature) = Signature::from_slice(&sig_bytes) else {
            // If this fails, the original signature was malformed.
            return false;
        };

        // 2. Create a MontgomeryPoint from the X25519 public key.
        let montgomery_point = MontgomeryPoint(*x25519_pub);

        // 3. Convert the MontgomeryPoint to an EdwardsPoint using the extracted sign bit.
        let edwards_point = match montgomery_point.to_edwards(sign_bit) {
            Some(p) => p,
            // If conversion fails, the public key is not a valid point.
            None => return false,
        };

        // 4. The compressed EdwardsPoint is the Ed25519 public key.
        let ed25519_pk_bytes = edwards_point.compress().to_bytes();
        let Ok(verifying_key) = VerifyingKey::from_bytes(&ed25519_pk_bytes) else {
            return false;
        };

        // 5. Use the standard Ed25519 verification with the CLEANED signature.
        verifying_key.verify(message, &cleaned_signature).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::xed25519;
    use ed25519_dalek::Signature;
    use std::convert::TryInto;

    #[test]
    fn test_xed25519_compatibility() {
        // --- Go Test Vectors ---
        let priv_seed_hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let x25519_pub_hex = "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c";
        let message_str = "This is a test message for XEd25519 compatibility.";
        let expected_sig_hex = "71fe4dc6c2d2bf043753e482f40de11e38f1cf4a95921860799201ee53e68601102d62908f5c149a0a1995f1c67a1ead120421918f827ebb5044f69e184e988d";

        let priv_seed: [u8; 32] = hex::decode(priv_seed_hex).unwrap().try_into().unwrap();
        let x25519_pub: [u8; 32] = hex::decode(x25519_pub_hex).unwrap().try_into().unwrap();
        let message = message_str.as_bytes();
        let expected_sig_bytes: [u8; 64] =
            hex::decode(expected_sig_hex).unwrap().try_into().unwrap();
        let expected_sig = Signature::from_slice(&expected_sig_bytes).unwrap();

        // 1. Verify the signature generated by the Go implementation. This is the crucial test.
        let is_go_sig_valid = xed25519::verify(&x25519_pub, message, &expected_sig);
        assert!(
            is_go_sig_valid,
            "Verification of Go-generated signature failed."
        );

        // 2. Sign the message in Rust. Assume a zero-nonce for deterministic testing.
        let random = [0u8; 64];
        let calculated_sig = xed25519::sign(&priv_seed, message, &random);

        // Derive X25519 public key from priv_seed for our own signature verification
        use curve25519_dalek::edwards::CompressedEdwardsY;
        let ed25519_pk = ed25519_dalek::SigningKey::from_bytes(&priv_seed).verifying_key();
        let ed25519_pk_bytes = ed25519_pk.as_bytes();
        let edwards_point = CompressedEdwardsY(*ed25519_pk_bytes).decompress().unwrap();
        let x25519_pub_ours: [u8; 32] = edwards_point.to_montgomery().to_bytes();

        // 3. Verify the signature we just created.
        let is_rust_sig_valid = xed25519::verify(&x25519_pub_ours, message, &calculated_sig);
        assert!(
            is_rust_sig_valid,
            "Verification of our own signature failed."
        );
    }
}
