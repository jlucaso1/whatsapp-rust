// src/socket/consts.rs
use crate::binary::token;

pub const ORIGIN: &str = "https://web.whatsapp.com";
pub const URL: &str = "wss://web.whatsapp.com/ws/chat";

pub const NOISE_START_PATTERN: &str = "Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00";

pub const WA_MAGIC_VALUE: u8 = 6;
pub const WA_CONN_HEADER: [u8; 4] = [b'W', b'A', WA_MAGIC_VALUE, token::DICT_VERSION as u8];

pub const FRAME_MAX_SIZE: usize = 2 << 23;
pub const FRAME_LENGTH_SIZE: usize = 3;
