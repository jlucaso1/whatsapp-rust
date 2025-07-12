use rand::{TryRngCore, rngs::OsRng};
use whatsapp_core::crypto::xed25519;
use x25519_dalek::{PublicKey, StaticSecret};

#[test]
fn test_xeddsa_sign_verify_roundtrip() {
    // 1. Setup keys
    let mut priv_bytes = [0u8; 32];
    OsRng.try_fill_bytes(&mut priv_bytes).unwrap();

    let dalek_priv_key = StaticSecret::from(priv_bytes);
    let dalek_pub_key = PublicKey::from(&dalek_priv_key);
    let pub_bytes = *dalek_pub_key.as_bytes();

    // 2. Sign the message using the clean wrapper function
    let message = b"This is a test message for the xeddsa wrapper";
    let signature = xed25519::sign(&priv_bytes, message);

    // 3. Verify the signature using the clean wrapper function
    let verify_result = xed25519::verify(&pub_bytes, message, &signature);
    assert!(
        verify_result,
        "Signature verification failed on a roundtrip test"
    );

    // 4. Verify that an incorrect message fails
    let wrong_message = b"This is not the message that was signed";
    let bad_result = xed25519::verify(&pub_bytes, wrong_message, &signature);
    assert!(
        !bad_result,
        "Signature verification succeeded with a wrong message"
    );
}
