use crate::client::Client;
use crate::mediaconn::MediaConn;
use anyhow::{Result, anyhow};

// Re-export core types and functionality
pub use whatsapp_core::download::{DownloadUtils, Downloadable, MediaType};

impl From<&MediaConn> for whatsapp_core::download::MediaConnection {
    fn from(conn: &MediaConn) -> Self {
        whatsapp_core::download::MediaConnection {
            hosts: conn
                .hosts
                .iter()
                .map(|h| whatsapp_core::download::MediaHost {
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

        // Convert to core types
        let core_media_conn = whatsapp_core::download::MediaConnection::from(&media_conn);
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
        request: &whatsapp_core::download::DownloadRequest,
    ) -> Result<Vec<u8>> {
        let url_clone = request.url.clone();
        let encrypted_data = tokio::task::spawn_blocking(move || {
            let resp = ureq::get(&url_clone).call()?;
            let len = resp
                .headers()
                .iter()
                .find_map(|(k, v)| {
                    if k.as_str().eq_ignore_ascii_case("Content-Length") {
                        v.to_str().ok()?.parse::<usize>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            let mut bytes: Vec<u8> = Vec::with_capacity(len);
            let mut body = resp.into_body();
            let mut reader = body.as_reader();
            std::io::Read::read_to_end(&mut reader, &mut bytes)?;
            Ok::<_, anyhow::Error>(bytes)
        })
        .await??;

        // Use core decryption logic
        DownloadUtils::decrypt_downloaded_media(
            &encrypted_data,
            &request.media_key,
            request.app_info,
        )
    }
}
