use crate::signal::ecc::key_pair::EcKeyPair;
use crate::signal::ecc::keys::EcPublicKey;
use crate::signal::identity::{IdentityKey, IdentityKeyPair};
use std::sync::Arc;

/// Parameters for a symmetric session where both parties are online.
pub struct SymmetricParameters {
    pub our_base_key: EcKeyPair,
    pub our_ratchet_key: EcKeyPair,
    pub our_identity_key_pair: IdentityKeyPair,
    pub their_base_key: Arc<dyn EcPublicKey>,
    pub their_ratchet_key: Arc<dyn EcPublicKey>,
    pub their_identity_key: IdentityKey,
}

/// Parameters when we are initiating the session (the "sender").
pub struct SenderParameters {
    pub our_identity_key_pair: IdentityKeyPair,
    pub our_base_key: EcKeyPair,
    pub their_identity_key: IdentityKey,
    pub their_signed_pre_key: Arc<dyn EcPublicKey>,
    pub their_one_time_pre_key: Option<Arc<dyn EcPublicKey>>,
}

/// Parameters when we are responding to a session initiation (the "receiver").
pub struct ReceiverParameters<'a> {
    pub our_identity_key_pair: IdentityKeyPair,
    pub our_signed_pre_key: EcKeyPair,
    pub our_one_time_pre_key: Option<&'a EcKeyPair>,
    pub their_identity_key: IdentityKey,
    pub their_base_key: Arc<dyn EcPublicKey>,
}
