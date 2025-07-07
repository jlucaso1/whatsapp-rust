use aes::Aes256;
use cbc::Encryptor;
use cipher::{BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const AES_BLOCK_SIZE: usize = 16;
const BUFFER_SIZE: usize = 32 * 1024; // 32KB buffer
const MAC_SIZE: usize = 10;

/// The result of a successful stream encryption operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptStreamResult {
    /// The SHA256 hash of the original, unencrypted plaintext.
    pub plain_hash: [u8; 32],
    /// The SHA256 hash of the final ciphertext, including padding and the appended MAC.
    pub cipher_hash: [u8; 32],
    /// The total number of bytes in the original plaintext.
    pub plain_size: u64,
    /// The total number of bytes written to the ciphertext stream.
    pub cipher_size: u64,
}

/// Custom error types for stream encryption.
#[derive(Debug, Error)]
pub enum CbcStreamError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Cipher operation failed")]
    Cipher,
    #[error("Invalid key or IV length for CBC mode: {0}")]
    InvalidLength(#[from] cipher::InvalidLength),
}

type Aes256CbcEnc = Encryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// Encrypts a stream of plaintext using AES-256-CBC, calculating hashes and a final MAC.
/// This is a direct port of whatsmeow's EncryptStream function.
pub async fn encrypt_stream<R, W>(
    key: &[u8],
    iv: &[u8],
    mac_key: &[u8],
    mut reader: R,
    mut writer: W,
) -> Result<EncryptStreamResult, CbcStreamError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // 1. Initialization
    let mut cbc_cipher = Aes256CbcEnc::new_from_slices(key, iv)?;
    let mut plain_hasher = Sha256::new();
    let mut cipher_hasher = Sha256::new();
    let mut cipher_mac = HmacSha256::new_from_slice(mac_key)
        .map_err(|_| CbcStreamError::InvalidLength(cipher::InvalidLength))?;

    cipher_mac.update(iv);

    let mut buf = vec![0u8; BUFFER_SIZE];
    let mut total_plain_size: u64 = 0;
    let mut processed_blocks = Vec::with_capacity(BUFFER_SIZE);

    // 2. Streaming Loop
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            // End of stream, apply padding to the last block in our processed_blocks buffer
            let padding_len = AES_BLOCK_SIZE - (processed_blocks.len() % AES_BLOCK_SIZE);
            let padding_val = padding_len as u8;
            processed_blocks.resize(processed_blocks.len() + padding_len, padding_val);
            break;
        }

        let chunk = &buf[..n];
        plain_hasher.update(chunk);
        total_plain_size += n as u64;

        std::io::Write::write_all(&mut processed_blocks, chunk)?;

        // Process full blocks from the buffer, leaving any remainder for the next iteration
        let blocks_to_encrypt_len = (processed_blocks.len() / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        if blocks_to_encrypt_len > 0 {
            {
                let blocks_to_encrypt_slice = &mut processed_blocks[..blocks_to_encrypt_len];

                let blocks = blocks_to_encrypt_slice.chunks_exact_mut(AES_BLOCK_SIZE);
                for block in blocks {
                    use cipher::generic_array::GenericArray;
                    let mut block_array = GenericArray::clone_from_slice(block);
                    cbc_cipher.encrypt_blocks_mut(std::slice::from_mut(&mut block_array));
                    block.copy_from_slice(&block_array);
                }

                cipher_mac.update(&*blocks_to_encrypt_slice);
                cipher_hasher.update(&*blocks_to_encrypt_slice);
                writer.write_all(&*blocks_to_encrypt_slice).await?;
            } // slice lifetime ends here

            processed_blocks.drain(..blocks_to_encrypt_len); // Now drain the processed part
        }
    }

    // Encrypt the final remaining (and padded) block
    if !processed_blocks.is_empty() {
        // Encrypt in-place as blocks
        let blocks = processed_blocks.chunks_exact_mut(AES_BLOCK_SIZE);
        for block in blocks {
            use cipher::generic_array::GenericArray;
            let mut block_array = GenericArray::clone_from_slice(block);
            cbc_cipher.encrypt_blocks_mut(std::slice::from_mut(&mut block_array));
            block.copy_from_slice(&block_array);
        }
        cipher_mac.update(&processed_blocks);
        cipher_hasher.update(&processed_blocks);
        writer.write_all(&processed_blocks).await?;
    }

    // 3. Finalization
    let mac_result = cipher_mac.finalize().into_bytes();
    let final_mac = &mac_result[..MAC_SIZE]; // Truncate to 10 bytes

    cipher_hasher.update(final_mac);
    writer.write_all(final_mac).await?;
    writer.flush().await?;

    let plain_hash: [u8; 32] = plain_hasher.finalize().into();
    let cipher_hash: [u8; 32] = cipher_hasher.finalize().into();
    let total_cipher_size = total_plain_size
        + (AES_BLOCK_SIZE - (total_plain_size as usize % AES_BLOCK_SIZE)) as u64
        + MAC_SIZE as u64;

    Ok(EncryptStreamResult {
        plain_hash,
        cipher_hash,
        plain_size: total_plain_size,
        cipher_size: total_cipher_size,
    })
}
