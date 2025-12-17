#![feature(portable_simd)]

pub use aes_gcm;
pub use wacore_appstate as appstate;
pub mod client;
pub mod download;
pub mod handshake;
pub mod history_sync;
pub use wacore_libsignal as libsignal;
pub mod messages;
pub mod net;
pub mod pair;
pub mod prekeys;
pub mod proto_helpers;
pub mod reporting_token;
pub mod request;
pub mod runtime;
pub mod send;
pub mod store;
pub mod types;
pub mod upload;
pub mod usync;
pub mod xml;
