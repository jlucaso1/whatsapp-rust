use anyhow::{Result, anyhow};
use base64::Engine;
use serde::Deserialize;
use wacore::download::MediaType;

use crate::client::Client;

#[derive(Debug, Clone)]
pub struct UploadResponse {
    pub url: String,
    pub direct_path: String,
    pub media_key: Vec<u8>,
    pub file_enc_sha256: Vec<u8>,
    pub file_sha256: Vec<u8>,
    pub file_length: u64,
}

#[derive(Deserialize)]
struct RawUploadResponse {
    url: String,
    direct_path: String,
}

impl Client {
    pub async fn upload(&self, data: Vec<u8>, media_type: MediaType) -> Result<UploadResponse> {
        let enc = tokio::task::spawn_blocking({
            let data = data.clone();
            move || wacore::upload::encrypt_media(&data, media_type)
        })
        .await??;

        let media_conn = self.refresh_media_conn(false).await?;
        let host = media_conn
            .hosts
            .first()
            .ok_or_else(|| anyhow!("No media hosts"))?;

        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(enc.file_enc_sha256);
        let mms_type = media_type.mms_type();
        let url = format!(
            "https://{}/mms/{}/{}?auth={}&token={}",
            host.hostname, mms_type, token, media_conn.auth, token
        );

        // Perform the synchronous upload in a blocking thread
        let raw: RawUploadResponse =
            tokio::task::spawn_blocking(move || -> Result<RawUploadResponse> {
                let mut resp = ureq::post(&url)
                    // FIX: ureq uses .set() for headers
                    .header("Content-Type", "application/octet-stream")
                    .header("Origin", "https://web.whatsapp.com")
                    .send(&enc.data_to_upload)?;

                if resp.status().as_u16() >= 400 {
                    return Err(anyhow!(
                        "Upload failed {} body={}",
                        resp.status(),
                        resp.body_mut().read_to_string().unwrap_or_default()
                    ));
                }

                Ok(resp.body_mut().read_json()?)
            })
            .await??;

        let result = UploadResponse {
            url: raw.url,
            direct_path: raw.direct_path,
            media_key: enc.media_key.to_vec(),
            file_enc_sha256: enc.file_enc_sha256.to_vec(),
            file_sha256: enc.file_sha256.to_vec(),
            file_length: data.len() as u64,
        };
        Ok(result)
    }
}
