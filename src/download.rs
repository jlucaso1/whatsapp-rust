use crate::client::Client;
use crate::mediaconn::MediaConn;
use anyhow::{Result, anyhow};
use std::io::{Seek, SeekFrom, Write};

pub use wacore::download::{DownloadUtils, Downloadable, MediaDecryption, MediaType};

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
    media_key: Option<Vec<u8>>,
    file_sha256: Vec<u8>,
    file_enc_sha256: Option<Vec<u8>>,
    file_length: u64,
    media_type: MediaType,
}

impl Downloadable for DownloadParams {
    fn direct_path(&self) -> Option<&str> {
        Some(&self.direct_path)
    }
    fn media_key(&self) -> Option<&[u8]> {
        self.media_key.as_deref()
    }
    fn file_enc_sha256(&self) -> Option<&[u8]> {
        self.file_enc_sha256.as_deref()
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
        let requests = self.prepare_requests(downloadable).await?;

        for request in requests {
            match self.download_with_request(&request).await {
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

    pub async fn download_to_file<W: Write + Seek + Send + Unpin>(
        &self,
        downloadable: &dyn Downloadable,
        mut writer: W,
    ) -> Result<()> {
        let data = self.download(downloadable).await?;
        writer.seek(SeekFrom::Start(0))?;
        writer.write_all(&data)?;
        Ok(())
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
            media_key: Some(media_key.to_vec()),
            file_sha256: file_sha256.to_vec(),
            file_enc_sha256: Some(file_enc_sha256.to_vec()),
            file_length,
            media_type,
        };
        self.download(&params).await
    }

    async fn prepare_requests(
        &self,
        downloadable: &dyn Downloadable,
    ) -> Result<Vec<wacore::download::DownloadRequest>> {
        let media_conn = self.refresh_media_conn(false).await?;
        let core_media_conn = wacore::download::MediaConnection::from(&media_conn);
        DownloadUtils::prepare_download_requests(downloadable, &core_media_conn)
    }

    async fn download_with_request(
        &self,
        request: &wacore::download::DownloadRequest,
    ) -> Result<Vec<u8>> {
        let url = request.url.clone();
        let decryption = request.decryption.clone();
        let http_request = crate::http::HttpRequest::get(url);
        let response = self.http_client.execute(http_request).await?;

        if response.status_code >= 300 {
            return Err(anyhow!(
                "Download failed with status: {}",
                response.status_code
            ));
        }

        match decryption {
            MediaDecryption::Encrypted {
                media_key,
                media_type,
            } => {
                tokio::task::spawn_blocking(move || {
                    DownloadUtils::decrypt_stream(&response.body[..], &media_key, media_type)
                })
                .await?
            }
            MediaDecryption::Plaintext { file_sha256 } => {
                let body = response.body;
                tokio::task::spawn_blocking(move || {
                    DownloadUtils::validate_plaintext_sha256(&body, &file_sha256)?;
                    Ok(body)
                })
                .await?
            }
        }
    }

    /// Downloads and decrypts media with streaming (constant memory usage).
    ///
    /// The entire HTTP download, decryption, and file write happen in a single
    /// blocking thread. The writer is seeked back to position 0 before returning.
    ///
    /// Memory usage: ~40KB regardless of file size (8KB read buffer + decrypt state).
    pub async fn download_to_writer<W: Write + Seek + Send + 'static>(
        &self,
        downloadable: &dyn Downloadable,
        writer: W,
    ) -> Result<W> {
        let requests = self.prepare_requests(downloadable).await?;

        let mut writer = writer;
        let mut last_err: Option<anyhow::Error> = None;
        for request in requests {
            let (w, result) = self
                .streaming_download_and_decrypt(&request, writer)
                .await?;
            writer = w;
            match result {
                Ok(()) => return Ok(writer),
                Err(e) => {
                    log::warn!(
                        "Failed to stream-download from URL {}: {:?}. Trying next host.",
                        request.url,
                        e
                    );
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

    /// Streaming variant of `download_from_params` that writes to a writer
    /// instead of buffering in memory.
    #[allow(clippy::too_many_arguments)]
    pub async fn download_from_params_to_writer<W: Write + Seek + Send + 'static>(
        &self,
        direct_path: &str,
        media_key: &[u8],
        file_sha256: &[u8],
        file_enc_sha256: &[u8],
        file_length: u64,
        media_type: MediaType,
        writer: W,
    ) -> Result<W> {
        let params = DownloadParams {
            direct_path: direct_path.to_string(),
            media_key: Some(media_key.to_vec()),
            file_sha256: file_sha256.to_vec(),
            file_enc_sha256: Some(file_enc_sha256.to_vec()),
            file_length,
            media_type,
        };
        self.download_to_writer(&params, writer).await
    }

    /// Internal: stream download + decrypt to a writer in one blocking thread.
    /// Always returns the writer (even on failure) so the caller can retry.
    async fn streaming_download_and_decrypt<W: Write + Seek + Send + 'static>(
        &self,
        request: &wacore::download::DownloadRequest,
        writer: W,
    ) -> Result<(W, Result<()>)> {
        let http_client = self.http_client.clone();
        let url = request.url.clone();
        let decryption = request.decryption.clone();

        tokio::task::spawn_blocking(move || {
            let mut writer = writer;

            // Seek to start before each attempt so retries start fresh
            if let Err(e) = writer.seek(SeekFrom::Start(0)) {
                return Ok((writer, Err(e.into())));
            }

            let result = (|| -> Result<()> {
                let http_request = crate::http::HttpRequest::get(url);
                let resp = http_client.execute_streaming(http_request)?;

                if resp.status_code >= 300 {
                    return Err(anyhow!("Download failed with status: {}", resp.status_code));
                }

                match &decryption {
                    MediaDecryption::Encrypted {
                        media_key,
                        media_type,
                    } => {
                        DownloadUtils::decrypt_stream_to_writer(
                            resp.body,
                            media_key,
                            *media_type,
                            &mut writer,
                        )?;
                    }
                    MediaDecryption::Plaintext { file_sha256 } => {
                        DownloadUtils::copy_and_validate_plaintext_to_writer(
                            resp.body,
                            file_sha256,
                            &mut writer,
                        )?;
                    }
                }
                writer.seek(SeekFrom::Start(0))?;
                Ok(())
            })();

            Ok((writer, result))
        })
        .await?
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
