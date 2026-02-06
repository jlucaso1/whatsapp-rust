#![feature(portable_simd)]
extern crate self as wacore;

pub use aes_gcm;
pub use wacore_appstate as appstate;
pub use wacore_noise as noise;

// Re-export derive macros
pub use wacore_derive::{EmptyNode, ProtocolNode, StringEnum};

pub mod client;
pub mod download;
pub mod iq;
pub mod protocol;
pub use wacore_noise::framing;
pub mod handshake;
pub mod history_sync;
pub mod ib;
pub use wacore_libsignal as libsignal;
pub mod messages;
pub mod net;
pub mod pair;
pub mod pair_code;
pub mod prekeys;
pub mod proto_helpers;
pub mod reporting_token;
pub mod request;
pub mod send;
pub mod stanza;
pub mod store;
pub mod types;
pub mod upload;
pub mod usync;
pub mod version;
pub mod xml;
