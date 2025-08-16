use crate::client::Client;
use crate::mediaconn::MediaConn;
use anyhow::{Result, anyhow};

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
}
