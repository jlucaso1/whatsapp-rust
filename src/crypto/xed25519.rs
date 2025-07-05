use ed25519_dalek::{Signature, SignatureError, SigningKey};
use rand::rngs::OsRng;
use xeddsa::xed25519::{PrivateKey, PublicKey};

pub fn sign_dalek(signing_key: &SigningKey, message: &[u8]) -> Signature {
    let priv_bytes = signing_key.to_bytes();
    let sig_bytes = sign(&priv_bytes, message);
    Signature::from_bytes(&sig_bytes)
}

pub fn verify_dalek(
    x25519_pub: &[u8; 32],
    message: &[u8],
    signature: &Signature,
) -> Result<(), SignatureError> {
    let sig_bytes = signature.to_bytes();
    verify(x25519_pub, message, &sig_bytes).map_err(|_| SignatureError::new())
}

pub fn sign(private_key_bytes: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let priv_key = PrivateKey(*private_key_bytes);
    let mut rng = OsRng;
    <PrivateKey as xeddsa::xeddsa::Sign<[u8; 64], [u8; 32], [u8; 32]>>::sign(
        &priv_key, message, rng,
    )
}

pub fn verify(
    public_key_bytes: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), xeddsa::xeddsa::Error> {
    let pub_key = PublicKey(*public_key_bytes);
    <PublicKey as xeddsa::xeddsa::Verify<[u8; 64], [u8; 32]>>::verify(&pub_key, message, signature)
}
