use libsignal_protocol::{CurveError, PrivateKey, PublicKey};

pub fn calculate_shared_secret(
    our_private_key: &PrivateKey,
    their_public_key: &PublicKey,
) -> Result<Box<[u8]>, CurveError> {
    our_private_key.calculate_agreement(their_public_key)
}
