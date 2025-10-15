use crate::client::Client;
use crate::mediaconn::MediaConn;
use anyhow::{Result, anyhow};
use std::io::{Read, Seek, SeekFrom, Write};

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

impl Client {
    pub async fn download(&self, downloadable: &dyn Downloadable) -> Result<Vec<u8>> {
        let media_conn = self.refresh_media_conn(false).await?;

        let core_media_conn = wacore::download::MediaConnection::from(&media_conn);
        let requests = DownloadUtils::prepare_download_requests(downloadable, &core_media_conn)?;

        for request in requests {
            match self.download_and_decrypt_stream(&request).await {
                Ok(mut decrypted_reader) => {
                    // Consume the stream and return the buffered data
                    return tokio::task::spawn_blocking(move || {
                        let mut buffer = Vec::new();
                        decrypted_reader.read_to_end(&mut buffer)?;
                        Ok(buffer)
                    })
                    .await?;
                }
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

    /// Returns a streaming reader for a downloadable item without buffering.
    /// This is useful for large files that should be processed incrementally.
    pub async fn download_stream(
        &self,
        downloadable: &dyn Downloadable,
    ) -> Result<Box<dyn Read + Send + Sync>> {
        let media_conn = self.refresh_media_conn(false).await?;

        let core_media_conn = wacore::download::MediaConnection::from(&media_conn);
        let requests = DownloadUtils::prepare_download_requests(downloadable, &core_media_conn)?;

        for request in requests {
            match self.download_and_decrypt_stream(&request).await {
                Ok(reader) => return Ok(reader),
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

    /// Downloads and decrypts a media file, returning a streaming reader.
    /// The reader is already decrypted and ready to be consumed.
    /// This avoids buffering the entire encrypted payload at the HTTP level.
    async fn download_and_decrypt_stream(
        &self,
        request: &wacore::download::DownloadRequest,
    ) -> Result<Box<dyn Read + Send + Sync>> {
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

        // Decrypt the streaming body in a blocking task since it's CPU-intensive.
        // The response.body is already a streaming reader, so we pass it directly to decrypt_stream.
        let decrypted_reader = tokio::task::spawn_blocking(move || {
            // decrypt_stream consumes the reader and returns the plaintext as Vec<u8>
            let plaintext = DownloadUtils::decrypt_stream(response.body, &media_key, app_info)?;
            // Wrap the plaintext in a Cursor to provide a Read interface
            let cursor = std::io::Cursor::new(plaintext);
            let reader: Box<dyn Read + Send + Sync> = Box::new(cursor);
            Ok::<_, anyhow::Error>(reader)
        })
        .await??;

        Ok(decrypted_reader)
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
            match self.download_and_decrypt_stream(&req).await {
                Ok(mut decrypted_stream) => {
                    // The stream is already decrypted. Copy it to the writer.
                    // The I/O here is synchronous, so we wrap it in spawn_blocking.
                    let write_result = tokio::task::spawn_blocking(move || {
                        let mut buffer = Vec::new();
                        std::io::copy(&mut decrypted_stream, &mut buffer)?;
                        Ok::<Vec<u8>, std::io::Error>(buffer)
                    })
                    .await??;

                    writer.seek(SeekFrom::Start(0))?;
                    writer.write_all(&write_result)?;
                    return Ok(());
                }
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("All media hosts failed")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn process_downloaded_media_ok() {
        let data = b"Hello media test";
        let enc = wacore::upload::encrypt_media(data, MediaType::Image).unwrap();
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let plaintext = DownloadUtils::verify_and_decrypt(
            &enc.data_to_upload,
            &enc.media_key,
            MediaType::Image,
        )
        .unwrap();
        cursor.write_all(&plaintext).unwrap();
        assert_eq!(cursor.into_inner(), data);
    }

    #[test]
    fn process_downloaded_media_bad_mac() {
        let data = b"Tamper";
        let mut enc = wacore::upload::encrypt_media(data, MediaType::Image).unwrap();
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
