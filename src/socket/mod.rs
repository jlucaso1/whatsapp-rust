// src/socket/mod.rs
pub mod consts;
pub mod error;
pub mod frame_socket;
pub mod noise_handshake;
pub mod noise_socket;

pub use error::{Result, SocketError};
pub use frame_socket::FrameSocket;
pub use noise_handshake::NoiseHandshake;
pub use noise_socket::NoiseSocket;
