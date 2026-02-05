use crate::client::Client;
use crate::mediaconn::MediaConn;
use anyhow::{Result, anyhow};
use std::io::{Seek, SeekFrom, Write};

pub use wacore::download::{DownloadUtils, Downloadable, MediaType};

impl From<&MediaConn> for wacore::download::MediaConnection {
    fn from(conn: &MediaConn) -> Self {
        wacore::download::MediaConnection {
            hosts: conn
                .hosts
                .iter()
                .map(|h| wacore::download::MediaHost {
                    hostname: h.hostname.clone(),
                })
                .collect(),
            auth: conn.auth.clone(),
        }
    }
}

/// Implements `Downloadable` from raw media parameters.
struct DownloadParams {
    direct_path: String,
    media_key: Vec<u8>,
    file_sha256: Vec<u8>,
    file_enc_sha256: Vec<u8>,
    file_length: u64,
    media_type: MediaType,
}

impl Downloadable for DownloadParams {
    fn direct_path(&self) -> Option<&str> {
        Some(&self.direct_path)
    }
    fn media_key(&self) -> Option<&[u8]> {
        Some(&self.media_key)
    }
    fn file_enc_sha256(&self) -> Option<&[u8]> {
        Some(&self.file_enc_sha256)
    }
    fn file_sha256(&self) -> Option<&[u8]> {
        Some(&self.file_sha256)
    }
    fn file_length(&self) -> Option<u64> {
        Some(self.file_length)
    }
    fn app_info(&self) -> MediaType {
        self.media_type
    }
}

impl Client {
    pub async fn download(&self, downloadable: &dyn Downloadable) -> Result<Vec<u8>> {
        let media_conn = self.refresh_media_conn(false).await?;

        let core_media_conn = wacore::download::MediaConnection::from(&media_conn);
        let requests = DownloadUtils::prepare_download_requests(downloadable, &core_media_conn)?;

        for request in requests {
            match self.download_and_decrypt_with_request(&request).await {
                Ok(data) => return Ok(data),
                Err(e) => {
                    log::warn!(
                        "Failed to download from URL {}: {:?}. Trying next host.",
                        request.url,
                        e
                    );
                    continue;
                }
            }
        }

        Err(anyhow!("Failed to download from all available media hosts"))
    }

    async fn download_and_decrypt_with_request(
        &self,
        request: &wacore::download::DownloadRequest,
    ) -> Result<Vec<u8>> {
        let url = request.url.clone();
        let media_key = request.media_key.clone();
        let app_info = request.app_info;
        let http_request = crate::http::HttpRequest::get(url);
        let response = self.http_client.execute(http_request).await?;

        if response.status_code >= 300 {
            return Err(anyhow!(
                "Download failed with status: {}",
                response.status_code
            ));
        }

        // Decrypt in a blocking thread since it's CPU-intensive
        tokio::task::spawn_blocking(move || {
            DownloadUtils::decrypt_stream(&response.body[..], &media_key, app_info)
        })
        .await?
    }

    pub async fn download_to_file<W: Write + Seek + Send + Unpin>(
        &self,
        downloadable: &dyn Downloadable,
        mut writer: W,
    ) -> Result<()> {
        let media_conn = self.refresh_media_conn(false).await?;
        let core_media_conn = wacore::download::MediaConnection::from(&media_conn);
        let requests = DownloadUtils::prepare_download_requests(downloadable, &core_media_conn)?;
        let mut last_err: Option<anyhow::Error> = None;
        for req in requests {
            match self
                .download_and_write(&req.url, &req.media_key, req.app_info, &mut writer)
                .await
            {
                Ok(()) => return Ok(()),
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            }
        }
        match last_err {
            Some(err) => Err(err),
            None => Err(anyhow!("Failed to download from all available media hosts")),
        }
    }

    /// Downloads and decrypts media from raw parameters without needing the original message.
    pub async fn download_from_params(
        &self,
        direct_path: &str,
        media_key: &[u8],
        file_sha256: &[u8],
        file_enc_sha256: &[u8],
        file_length: u64,
        media_type: MediaType,
    ) -> Result<Vec<u8>> {
        let params = DownloadParams {
            direct_path: direct_path.to_string(),
            media_key: media_key.to_vec(),
            file_sha256: file_sha256.to_vec(),
            file_enc_sha256: file_enc_sha256.to_vec(),
            file_length,
            media_type,
        };
        self.download(&params).await
    }

    async fn download_and_write<W: Write + Seek + Send + Unpin>(
        &self,
        url: &str,
        media_key: &[u8],
        media_type: MediaType,
        writer: &mut W,
    ) -> Result<()> {
        let http_request = crate::http::HttpRequest::get(url);
        let response = self.http_client.execute(http_request).await?;

        if response.status_code >= 300 {
            return Err(anyhow!(
                "Download failed with status: {}",
                response.status_code
            ));
        }

        let media_key = media_key.to_vec();
        let encrypted_bytes = response.body;

        // Decrypt and verify in a blocking thread since it's CPU-intensive
        let plaintext = tokio::task::spawn_blocking(move || {
            DownloadUtils::verify_and_decrypt(&encrypted_bytes, &media_key, media_type)
        })
        .await??;

        writer.seek(SeekFrom::Start(0))?;
        writer.write_all(&plaintext)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn process_downloaded_media_ok() {
        let data = b"Hello media test";
        let enc = wacore::upload::encrypt_media(data, MediaType::Image)
            .expect("encryption should succeed");
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let plaintext = DownloadUtils::verify_and_decrypt(
            &enc.data_to_upload,
            &enc.media_key,
            MediaType::Image,
        )
        .expect("decryption should succeed");
        cursor.write_all(&plaintext).expect("write should succeed");
        assert_eq!(cursor.into_inner(), data);
    }

    #[test]
    fn process_downloaded_media_bad_mac() {
        let data = b"Tamper";
        let mut enc = wacore::upload::encrypt_media(data, MediaType::Image)
            .expect("encryption should succeed");
        let last = enc.data_to_upload.len() - 1;
        enc.data_to_upload[last] ^= 0x01;

        let err = DownloadUtils::verify_and_decrypt(
            &enc.data_to_upload,
            &enc.media_key,
            MediaType::Image,
        )
        .unwrap_err();

        assert!(err.to_string().to_lowercase().contains("invalid mac"));
    }
}
