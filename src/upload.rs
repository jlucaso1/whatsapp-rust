use anyhow::{Result, anyhow};
use base64::Engine;
use serde::Deserialize;
use wacore::download::MediaType;

use crate::client::Client;
use crate::http::HttpRequest;

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
        let scheme = "https";
        let url = format!(
            "{}://{}/mms/{}/{}?auth={}&token={}",
            scheme, host.hostname, mms_type, token, media_conn.auth, token
        );

        let request = HttpRequest::post(url)
            .with_header("Content-Type", "application/octet-stream")
            .with_header("Origin", "https://web.whatsapp.com")
            .with_body(enc.data_to_upload);

        let response = self.http_client.execute(request).await?;

        if response.status_code >= 400 {
            let body_str = match response.body_string() {
                Ok(body) => body,
                Err(body_err) => {
                    return Err(anyhow!(
                        "Upload failed {} and failed to read response body: {}",
                        response.status_code,
                        body_err
                    ));
                }
            };
            return Err(anyhow!(
                "Upload failed {} body={}",
                response.status_code,
                body_str
            ));
        }

        let raw: RawUploadResponse = serde_json::from_slice(&response.body)?;

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
