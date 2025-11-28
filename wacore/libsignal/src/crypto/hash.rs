//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

use crate::crypto::{Error, Result};

/// Output size constants for zero-allocation finalization
pub const SHA1_OUTPUT_SIZE: usize = 20;
pub const SHA256_OUTPUT_SIZE: usize = 32;
pub const SHA512_OUTPUT_SIZE: usize = 64;

#[derive(Clone)]
pub enum CryptographicMac {
    HmacSha256(Hmac<Sha256>),
    HmacSha1(Hmac<Sha1>),
    HmacSha512(Hmac<Sha512>),
}

impl CryptographicMac {
    pub fn new(algo: &str, key: &[u8]) -> Result<Self> {
        match algo {
            "HMACSha1" | "HmacSha1" => Ok(Self::HmacSha1(
                Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length"),
            )),
            "HMACSha256" | "HmacSha256" => Ok(Self::HmacSha256(
                Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length"),
            )),
            "HMACSha512" | "HmacSha512" => Ok(Self::HmacSha512(
                Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts any key length"),
            )),
            _ => Err(Error::UnknownAlgorithm("MAC", algo.to_string())),
        }
    }

    pub fn update(&mut self, input: &[u8]) {
        match self {
            Self::HmacSha1(sha1) => sha1.update(input),
            Self::HmacSha256(sha256) => sha256.update(input),
            Self::HmacSha512(sha512) => sha512.update(input),
        }
    }

    pub fn update_and_get(&mut self, input: &[u8]) -> &mut Self {
        self.update(input);
        self
    }

    pub fn finalize(&mut self) -> Vec<u8> {
        match self {
            Self::HmacSha1(sha1) => sha1.finalize_reset().into_bytes().to_vec(),
            Self::HmacSha256(sha256) => sha256.finalize_reset().into_bytes().to_vec(),
            Self::HmacSha512(sha512) => sha512.finalize_reset().into_bytes().to_vec(),
        }
    }

    /// Zero-allocation finalization that writes the MAC result into a provided buffer.
    /// Returns the number of bytes written, or an error if the buffer is too small.
    ///
    /// Buffer size requirements:
    /// - HmacSha1: 20 bytes
    /// - HmacSha256: 32 bytes
    /// - HmacSha512: 64 bytes
    pub fn finalize_into(&mut self, out: &mut [u8]) -> Result<usize> {
        match self {
            Self::HmacSha1(sha1) => {
                if out.len() < SHA1_OUTPUT_SIZE {
                    return Err(Error::OutputBufferTooSmall {
                        required: SHA1_OUTPUT_SIZE,
                        provided: out.len(),
                    });
                }
                let result = sha1.finalize_reset().into_bytes();
                out[..SHA1_OUTPUT_SIZE].copy_from_slice(&result);
                Ok(SHA1_OUTPUT_SIZE)
            }
            Self::HmacSha256(sha256) => {
                if out.len() < SHA256_OUTPUT_SIZE {
                    return Err(Error::OutputBufferTooSmall {
                        required: SHA256_OUTPUT_SIZE,
                        provided: out.len(),
                    });
                }
                let result = sha256.finalize_reset().into_bytes();
                out[..SHA256_OUTPUT_SIZE].copy_from_slice(&result);
                Ok(SHA256_OUTPUT_SIZE)
            }
            Self::HmacSha512(sha512) => {
                if out.len() < SHA512_OUTPUT_SIZE {
                    return Err(Error::OutputBufferTooSmall {
                        required: SHA512_OUTPUT_SIZE,
                        provided: out.len(),
                    });
                }
                let result = sha512.finalize_reset().into_bytes();
                out[..SHA512_OUTPUT_SIZE].copy_from_slice(&result);
                Ok(SHA512_OUTPUT_SIZE)
            }
        }
    }

    /// Returns the output size in bytes for this MAC algorithm.
    pub fn output_size(&self) -> usize {
        match self {
            Self::HmacSha1(_) => SHA1_OUTPUT_SIZE,
            Self::HmacSha256(_) => SHA256_OUTPUT_SIZE,
            Self::HmacSha512(_) => SHA512_OUTPUT_SIZE,
        }
    }

    /// Zero-allocation finalization into a fixed-size array for SHA-256 HMAC.
    /// This is the most common case and avoids any heap allocation.
    pub fn finalize_sha256_array(&mut self) -> Result<[u8; SHA256_OUTPUT_SIZE]> {
        match self {
            Self::HmacSha256(sha256) => {
                let result = sha256.finalize_reset().into_bytes();
                Ok(result.into())
            }
            _ => Err(Error::UnknownAlgorithm(
                "MAC",
                "Expected HmacSha256 for finalize_sha256_array".to_string(),
            )),
        }
    }
}

#[derive(Clone)]
pub enum CryptographicHash {
    Sha1(Sha1),
    Sha256(Sha256),
    Sha512(Sha512),
}

impl CryptographicHash {
    pub fn new(algo: &str) -> Result<Self> {
        match algo {
            "SHA-1" | "SHA1" | "Sha1" => Ok(Self::Sha1(Sha1::new())),
            "SHA-256" | "SHA256" | "Sha256" => Ok(Self::Sha256(Sha256::new())),
            "SHA-512" | "SHA512" | "Sha512" => Ok(Self::Sha512(Sha512::new())),
            _ => Err(Error::UnknownAlgorithm("digest", algo.to_string())),
        }
    }

    pub fn update(&mut self, input: &[u8]) {
        match self {
            Self::Sha1(sha1) => sha1.update(input),
            Self::Sha256(sha256) => sha256.update(input),
            Self::Sha512(sha512) => sha512.update(input),
        }
    }

    pub fn finalize(&mut self) -> Vec<u8> {
        match self {
            Self::Sha1(sha1) => sha1.finalize_reset().to_vec(),
            Self::Sha256(sha256) => sha256.finalize_reset().to_vec(),
            Self::Sha512(sha512) => sha512.finalize_reset().to_vec(),
        }
    }

    /// Zero-allocation finalization that writes the hash result into a provided buffer.
    /// Returns the number of bytes written, or an error if the buffer is too small.
    ///
    /// Buffer size requirements:
    /// - Sha1: 20 bytes
    /// - Sha256: 32 bytes
    /// - Sha512: 64 bytes
    pub fn finalize_into(&mut self, out: &mut [u8]) -> Result<usize> {
        match self {
            Self::Sha1(sha1) => {
                if out.len() < SHA1_OUTPUT_SIZE {
                    return Err(Error::OutputBufferTooSmall {
                        required: SHA1_OUTPUT_SIZE,
                        provided: out.len(),
                    });
                }
                let result = sha1.finalize_reset();
                out[..SHA1_OUTPUT_SIZE].copy_from_slice(&result);
                Ok(SHA1_OUTPUT_SIZE)
            }
            Self::Sha256(sha256) => {
                if out.len() < SHA256_OUTPUT_SIZE {
                    return Err(Error::OutputBufferTooSmall {
                        required: SHA256_OUTPUT_SIZE,
                        provided: out.len(),
                    });
                }
                let result = sha256.finalize_reset();
                out[..SHA256_OUTPUT_SIZE].copy_from_slice(&result);
                Ok(SHA256_OUTPUT_SIZE)
            }
            Self::Sha512(sha512) => {
                if out.len() < SHA512_OUTPUT_SIZE {
                    return Err(Error::OutputBufferTooSmall {
                        required: SHA512_OUTPUT_SIZE,
                        provided: out.len(),
                    });
                }
                let result = sha512.finalize_reset();
                out[..SHA512_OUTPUT_SIZE].copy_from_slice(&result);
                Ok(SHA512_OUTPUT_SIZE)
            }
        }
    }

    /// Returns the output size in bytes for this hash algorithm.
    pub fn output_size(&self) -> usize {
        match self {
            Self::Sha1(_) => SHA1_OUTPUT_SIZE,
            Self::Sha256(_) => SHA256_OUTPUT_SIZE,
            Self::Sha512(_) => SHA512_OUTPUT_SIZE,
        }
    }

    /// Zero-allocation finalization into a fixed-size array for SHA-256.
    /// This is the most common case and avoids any heap allocation.
    pub fn finalize_sha256_array(&mut self) -> Result<[u8; SHA256_OUTPUT_SIZE]> {
        match self {
            Self::Sha256(sha256) => {
                let result = sha256.finalize_reset();
                Ok(result.into())
            }
            _ => Err(Error::UnknownAlgorithm(
                "digest",
                "Expected Sha256 for finalize_sha256_array".to_string(),
            )),
        }
    }
}
