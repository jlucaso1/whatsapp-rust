use crate::socket::error::{Result, SocketError};
use aes_gcm::aead::Aead;
use aes_gcm::Aes256Gcm;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

pub fn generate_iv(counter: u32) -> [u8; 12] {
    let mut iv = [0u8; 12];
    iv[8..].copy_from_slice(&counter.to_be_bytes());
    iv
}

use crate::socket::FrameSocket;
use tokio::sync::Mutex;

pub struct NoiseSocket {
    pub(crate) frame_socket: Arc<Mutex<FrameSocket>>,
    write_key: Aes256Gcm,
    read_key: Aes256Gcm,
    write_counter: Arc<AtomicU32>,
    read_counter: Arc<AtomicU32>,
}

impl NoiseSocket {
    /// Marshals a Node and sends it as a frame (for compatibility with request.rs).
    pub async fn send_node(&self, node: &crate::binary::node::Node) -> Result<()> {
        let payload = crate::binary::marshal(node)
            .map_err(|e| SocketError::Crypto(format!("Marshal error: {e:?}")))?;
        self.send_frame(&payload).await
    }
    pub fn new(
        frame_socket: Arc<Mutex<FrameSocket>>,
        write_key: Aes256Gcm,
        read_key: Aes256Gcm,
    ) -> Self {
        Self {
            frame_socket,
            write_key,
            read_key,
            write_counter: Arc::new(AtomicU32::new(0)),
            read_counter: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Encrypts the payload and sends it via FrameSocket.
    pub async fn send_frame(&self, plaintext: &[u8]) -> Result<()> {
        let counter = self.write_counter.fetch_add(1, Ordering::SeqCst);
        let iv = generate_iv(counter);
        let ciphertext = self
            .write_key
            .encrypt(iv.as_ref().into(), plaintext)
            .map_err(|e| SocketError::Crypto(e.to_string()))?;

        let fs = self.frame_socket.clone();
        let guard = fs.lock().await;
        guard.send_frame(&ciphertext).await
    }

    pub fn decrypt_frame(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let counter = self.read_counter.fetch_add(1, Ordering::SeqCst);
        let iv = generate_iv(counter);
        self.read_key
            .decrypt(iv.as_ref().into(), ciphertext)
            .map_err(|e| SocketError::Crypto(e.to_string()))
    }

    /// Test-only: receive and decrypt a full node from the underlying FrameSocket.
    #[cfg(test)]
    pub async fn recv_node(&self) -> anyhow::Result<crate::binary::node::Node> {
        let mut fs_guard = self.frame_socket.lock().await;
        let frame = fs_guard.recv_frame_for_test().await?;
        let decrypted = self
            .decrypt_frame(&frame)
            .map_err(|e| anyhow::anyhow!("Noise decrypt error: {:?}", e))?;
        let unpacked = crate::binary::util::unpack(&decrypted)?;
        Ok(crate::binary::unmarshal_ref(unpacked.as_ref())?.to_owned())
    }
}
