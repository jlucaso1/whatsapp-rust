//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use hmac::{HmacReset, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

use crate::crypto::{Error, Result};

/// Output size constants for zero-allocation finalization
pub const SHA1_OUTPUT_SIZE: usize = 20;
pub const SHA256_OUTPUT_SIZE: usize = 32;
pub const SHA512_OUTPUT_SIZE: usize = 64;

#[derive(Clone)]
pub enum CryptographicMac {
    HmacSha256(HmacReset<Sha256>),
    HmacSha1(HmacReset<Sha1>),
    HmacSha512(HmacReset<Sha512>),
}

impl CryptographicMac {
    pub fn new(algo: &str, key: &[u8]) -> Result<Self> {
        match algo {
            "HMACSha1" | "HmacSha1" => Ok(Self::HmacSha1(
                HmacReset::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length"),
            )),
            "HMACSha256" | "HmacSha256" => Ok(Self::HmacSha256(
                HmacReset::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length"),
            )),
            "HMACSha512" | "HmacSha512" => Ok(Self::HmacSha512(
                HmacReset::<Sha512>::new_from_slice(key).expect("HMAC accepts any key length"),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// NIST FIPS 180-4 example: SHA-256("abc")
    #[test]
    fn test_sha256_known_answer() {
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];

        let mut hash = CryptographicHash::new("SHA-256").unwrap();
        hash.update(b"abc");
        let result = hash.finalize();
        assert_eq!(result, expected, "SHA-256('abc') NIST vector mismatch");
    }

    /// RFC 4231 Test Case 2: HMAC-SHA256 with key="Jefe", data="what do ya want for nothing?"
    #[test]
    fn test_hmac_sha256_rfc4231_tc2() {
        let expected: [u8; 32] = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ];

        let mut mac = CryptographicMac::new("HmacSha256", b"Jefe").unwrap();
        mac.update(b"what do ya want for nothing?");
        let result = mac.finalize();
        assert_eq!(result, expected, "HMAC-SHA256 RFC 4231 TC2 mismatch");
    }

    /// finalize_sha256_array() returns a [u8; 32] matching the Vec-based finalize()
    #[test]
    fn test_mac_finalize_sha256_array_returns_correct_type() {
        let key = b"test-key";
        let data = b"test-data";

        let mut mac1 = CryptographicMac::new("HmacSha256", key).unwrap();
        mac1.update(data);
        let vec_result = mac1.finalize();

        let mut mac2 = CryptographicMac::new("HmacSha256", key).unwrap();
        mac2.update(data);
        let array_result: [u8; SHA256_OUTPUT_SIZE] = mac2.finalize_sha256_array().unwrap();

        assert_eq!(&vec_result[..], &array_result[..]);
    }

    /// finalize_sha256_array() on a non-SHA256 MAC returns an error
    #[test]
    fn test_mac_finalize_sha256_array_wrong_variant() {
        let mut mac = CryptographicMac::new("HmacSha1", b"key").unwrap();
        mac.update(b"data");
        assert!(mac.finalize_sha256_array().is_err());
    }

    /// Hash finalize_sha256_array() returns a [u8; 32] matching Vec finalize()
    #[test]
    fn test_hash_finalize_sha256_array() {
        let mut h1 = CryptographicHash::new("SHA-256").unwrap();
        h1.update(b"hello");
        let vec_result = h1.finalize();

        let mut h2 = CryptographicHash::new("SHA-256").unwrap();
        h2.update(b"hello");
        let array_result: [u8; SHA256_OUTPUT_SIZE] = h2.finalize_sha256_array().unwrap();

        assert_eq!(&vec_result[..], &array_result[..]);
    }

    /// Hash finalize_sha256_array() on a non-SHA256 hash returns an error
    #[test]
    fn test_hash_finalize_sha256_array_wrong_variant() {
        let mut h = CryptographicHash::new("SHA-512").unwrap();
        h.update(b"data");
        assert!(h.finalize_sha256_array().is_err());
    }

    /// MAC finalize_into() writes correct bytes and returns the right length
    #[test]
    fn test_mac_finalize_into_correct_buffer() {
        let mut mac = CryptographicMac::new("HmacSha256", b"key").unwrap();
        mac.update(b"data");
        let expected = {
            let mut m = CryptographicMac::new("HmacSha256", b"key").unwrap();
            m.update(b"data");
            m.finalize()
        };

        let mut buf = [0u8; 64]; // larger than needed
        let n = mac.finalize_into(&mut buf).unwrap();
        assert_eq!(n, SHA256_OUTPUT_SIZE);
        assert_eq!(&buf[..n], &expected[..]);
    }

    /// MAC finalize_into() returns error when buffer is too small
    #[test]
    fn test_mac_finalize_into_too_small_buffer() {
        let mut mac = CryptographicMac::new("HmacSha256", b"key").unwrap();
        mac.update(b"data");

        let mut buf = [0u8; 16]; // 16 < 32 required
        let result = mac.finalize_into(&mut buf);
        assert!(result.is_err());
    }

    /// Hash finalize_into() writes correct bytes and returns the right length
    #[test]
    fn test_hash_finalize_into_correct_buffer() {
        let mut hash = CryptographicHash::new("SHA-256").unwrap();
        hash.update(b"data");
        let expected = {
            let mut h = CryptographicHash::new("SHA-256").unwrap();
            h.update(b"data");
            h.finalize()
        };

        let mut buf = [0u8; 64];
        let n = hash.finalize_into(&mut buf).unwrap();
        assert_eq!(n, SHA256_OUTPUT_SIZE);
        assert_eq!(&buf[..n], &expected[..]);
    }

    /// Hash finalize_into() returns error when buffer is too small
    #[test]
    fn test_hash_finalize_into_too_small_buffer() {
        let mut hash = CryptographicHash::new("SHA-512").unwrap();
        hash.update(b"data");

        let mut buf = [0u8; 32]; // 32 < 64 required
        let result = hash.finalize_into(&mut buf);
        assert!(result.is_err());
    }

    /// output_size() returns the correct constant for each hash variant
    #[test]
    fn test_hash_output_size() {
        let sha1 = CryptographicHash::new("SHA-1").unwrap();
        assert_eq!(sha1.output_size(), SHA1_OUTPUT_SIZE);
        assert_eq!(sha1.output_size(), 20);

        let sha256 = CryptographicHash::new("SHA-256").unwrap();
        assert_eq!(sha256.output_size(), SHA256_OUTPUT_SIZE);
        assert_eq!(sha256.output_size(), 32);

        let sha512 = CryptographicHash::new("SHA-512").unwrap();
        assert_eq!(sha512.output_size(), SHA512_OUTPUT_SIZE);
        assert_eq!(sha512.output_size(), 64);
    }

    /// output_size() returns the correct constant for each MAC variant
    #[test]
    fn test_mac_output_size() {
        let hmac_sha1 = CryptographicMac::new("HmacSha1", b"k").unwrap();
        assert_eq!(hmac_sha1.output_size(), SHA1_OUTPUT_SIZE);
        assert_eq!(hmac_sha1.output_size(), 20);

        let hmac_sha256 = CryptographicMac::new("HmacSha256", b"k").unwrap();
        assert_eq!(hmac_sha256.output_size(), SHA256_OUTPUT_SIZE);
        assert_eq!(hmac_sha256.output_size(), 32);

        let hmac_sha512 = CryptographicMac::new("HmacSha512", b"k").unwrap();
        assert_eq!(hmac_sha512.output_size(), SHA512_OUTPUT_SIZE);
        assert_eq!(hmac_sha512.output_size(), 64);
    }

    /// Unknown hash algorithm returns an error
    #[test]
    fn test_unknown_hash_algorithm() {
        let result = CryptographicHash::new("MD5");
        assert!(result.is_err());
    }

    /// Unknown MAC algorithm returns an error
    #[test]
    fn test_unknown_mac_algorithm() {
        let result = CryptographicMac::new("HmacMd5", b"key");
        assert!(result.is_err());
    }

    /// All accepted hash algorithm name aliases work
    #[test]
    fn test_hash_algorithm_aliases() {
        assert!(CryptographicHash::new("SHA-1").is_ok());
        assert!(CryptographicHash::new("SHA1").is_ok());
        assert!(CryptographicHash::new("Sha1").is_ok());

        assert!(CryptographicHash::new("SHA-256").is_ok());
        assert!(CryptographicHash::new("SHA256").is_ok());
        assert!(CryptographicHash::new("Sha256").is_ok());

        assert!(CryptographicHash::new("SHA-512").is_ok());
        assert!(CryptographicHash::new("SHA512").is_ok());
        assert!(CryptographicHash::new("Sha512").is_ok());
    }

    /// All accepted MAC algorithm name aliases work
    #[test]
    fn test_mac_algorithm_aliases() {
        assert!(CryptographicMac::new("HMACSha1", b"k").is_ok());
        assert!(CryptographicMac::new("HmacSha1", b"k").is_ok());

        assert!(CryptographicMac::new("HMACSha256", b"k").is_ok());
        assert!(CryptographicMac::new("HmacSha256", b"k").is_ok());

        assert!(CryptographicMac::new("HMACSha512", b"k").is_ok());
        assert!(CryptographicMac::new("HmacSha512", b"k").is_ok());
    }
}
