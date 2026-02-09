//! Noise Protocol implementation for WhatsApp with AES-256-GCM.
//!
//! This crate provides both a generic Noise Protocol XX state machine and
//! WhatsApp-specific handshake utilities.
//!
//! # Structure
//!
//! - `NoiseState` - Generic Noise XX protocol state machine
//! - `NoiseHandshake` - WhatsApp-specific wrapper with libsignal DH
//! - `HandshakeUtils` - WhatsApp protocol message building/parsing
//!
//! # Example (Generic)
//!
//! ```ignore
//! use wacore_noise::{NoiseState, generate_iv};
//!
//! let mut noise = NoiseState::new(b"Noise_XX_25519_AESGCM_SHA256\0\0\0\0", &prologue)?;
//! noise.authenticate(&my_ephemeral_public);
//! noise.mix_key(&shared_secret)?;
//! let ciphertext = noise.encrypt(plaintext)?;
//! let keys = noise.split()?;
//! ```
//!
//! # Example (WhatsApp)
//!
//! ```ignore
//! use wacore_noise::{NoiseHandshake, HandshakeUtils};
//!
//! let mut nh = NoiseHandshake::new(NOISE_START_PATTERN, &WA_CONN_HEADER)?;
//! nh.authenticate(&ephemeral_public);
//! nh.mix_shared_secret(&private_key, &their_public)?;
//! let (write_key, read_key) = nh.finish()?;
//! ```

mod edge_routing;
mod error;
pub mod framing;
mod handshake;
mod state;

pub use aes_gcm::Aes256Gcm;
pub use edge_routing::{
    EdgeRoutingError, MAX_EDGE_ROUTING_LEN, build_edge_routing_preintro, build_handshake_header,
};
pub use error::{NoiseError, Result};
pub use handshake::{
    HandshakeError, HandshakeState, HandshakeUtils, NoiseHandshake, Result as HandshakeResult,
    WA_CERT_PUB_KEY,
};
pub use state::{NoiseCipher, NoiseKeys, NoiseState, generate_iv};
