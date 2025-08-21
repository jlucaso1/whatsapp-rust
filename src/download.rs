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
        tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
            let resp = ureq::get(&url).call()?;
            let mut body = resp.into_body();
            let reader = body.as_reader();
            DownloadUtils::decrypt_stream(reader, &media_key, app_info)
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
        Err(last_err.unwrap_or_else(|| anyhow!("All media hosts failed")))
    }

    async fn download_and_write<W: Write + Seek + Send + Unpin>(
        &self,
        url: &str,
        media_key: &[u8],
        media_type: MediaType,
        writer: &mut W,
    ) -> Result<()> {
        let url = url.to_string();
        let media_key = media_key.to_vec();

        let plaintext = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
            let mut resp = ureq::get(&url).call()?;
            if resp.status().as_u16() >= 300 {
                return Err(anyhow!("Download failed with status: {}", resp.status()));
            }

            let encrypted_bytes = resp.body_mut().read_to_vec()?;

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
