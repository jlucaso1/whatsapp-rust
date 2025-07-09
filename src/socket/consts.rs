// src/socket/consts.rs
use crate::binary::token;

pub const ORIGIN: &str = "https://web.whatsapp.com";
use std::sync::{LazyLock, RwLock};

pub static URL: LazyLock<RwLock<String>> =
    LazyLock::new(|| RwLock::new("wss://web.whatsapp.com/ws/chat".to_string()));

pub const NOISE_START_PATTERN: &str = "Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00";

pub const WA_MAGIC_VALUE: u8 = 6;
pub const WA_CONN_HEADER: [u8; 4] = [b'W', b'A', WA_MAGIC_VALUE, token::DICT_VERSION];

pub const FRAME_MAX_SIZE: usize = 2 << 23;
pub const FRAME_LENGTH_SIZE: usize = 3;
