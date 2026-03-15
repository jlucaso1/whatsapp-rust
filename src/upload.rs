use anyhow::{Result, anyhow};
use base64::Engine;
use serde::Deserialize;
use wacore::download::MediaType;

use crate::client::Client;
use crate::http::{HttpRequest, HttpResponse};

fn is_media_auth_error(status_code: u16) -> bool {
    matches!(status_code, 401 | 403)
}

fn build_upload_request(
    hostname: &str,
    mms_type: &str,
    auth: &str,
    token: &str,
    body: Vec<u8>,
) -> HttpRequest {
    let url = format!("https://{hostname}/mms/{mms_type}/{token}?auth={auth}&token={token}");

    HttpRequest::post(url)
        .with_header("Content-Type", "application/octet-stream")
        .with_header("Origin", "https://web.whatsapp.com")
        .with_body(body)
}

fn upload_error_from_response(response: HttpResponse) -> anyhow::Error {
    match response.body_string() {
        Ok(body) => anyhow!("Upload failed {} body={}", response.status_code, body),
        Err(body_err) => anyhow!(
            "Upload failed {} and failed to read response body: {}",
            response.status_code,
            body_err
        ),
    }
}

async fn upload_media_with_retry<
    GetMediaConn,
    GetMediaConnFut,
    InvalidateMediaConn,
    InvalidateMediaConnFut,
    ExecuteRequest,
    ExecuteRequestFut,
>(
    enc: &wacore::upload::EncryptedMedia,
    media_type: MediaType,
    file_length: u64,
    mut get_media_conn: GetMediaConn,
    mut invalidate_media_conn: InvalidateMediaConn,
    mut execute_request: ExecuteRequest,
) -> Result<UploadResponse>
where
    GetMediaConn: FnMut(bool) -> GetMediaConnFut,
    GetMediaConnFut: std::future::Future<Output = Result<crate::mediaconn::MediaConn>>,
    InvalidateMediaConn: FnMut() -> InvalidateMediaConnFut,
    InvalidateMediaConnFut: std::future::Future<Output = ()>,
    ExecuteRequest: FnMut(HttpRequest) -> ExecuteRequestFut,
    ExecuteRequestFut: std::future::Future<Output = Result<HttpResponse>>,
{
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(enc.file_enc_sha256);
    let mms_type = media_type.mms_type();
    let mut force_refresh = false;
    let mut last_error: Option<anyhow::Error> = None;

    for attempt in 0..=1 {
        let media_conn = get_media_conn(force_refresh).await?;
        if media_conn.hosts.is_empty() {
            return Err(anyhow!("No media hosts"));
        }

        let mut retry_with_fresh_auth = false;

        for host in &media_conn.hosts {
            let request = build_upload_request(
                &host.hostname,
                mms_type,
                &media_conn.auth,
                &token,
                enc.data_to_upload.clone(),
            );

            let response = match execute_request(request).await {
                Ok(response) => response,
                Err(err) => {
                    last_error = Some(err);
                    continue;
                }
            };

            if response.status_code < 400 {
                let raw: RawUploadResponse = serde_json::from_slice(&response.body)?;
                return Ok(UploadResponse {
                    url: raw.url,
                    direct_path: raw.direct_path,
                    media_key: enc.media_key.to_vec(),
                    file_enc_sha256: enc.file_enc_sha256.to_vec(),
                    file_sha256: enc.file_sha256.to_vec(),
                    file_length,
                });
            }

            let status_code = response.status_code;
            let err = upload_error_from_response(response);

            if is_media_auth_error(status_code) {
                if attempt == 0 {
                    invalidate_media_conn().await;
                    force_refresh = true;
                    retry_with_fresh_auth = true;
                    break;
                }

                return Err(err);
            }

            last_error = Some(err);
        }

        if !retry_with_fresh_auth {
            break;
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("Failed to upload to all available media hosts")))
}

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

        upload_media_with_retry(
            &enc,
            media_type,
            data.len() as u64,
            |force| async move { self.refresh_media_conn(force).await.map_err(Into::into) },
            || async { self.invalidate_media_conn().await },
            |request| async move { self.http_client.execute(request).await },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediaconn::{MediaConn, MediaConnHost};
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::sync::Mutex;

    fn media_conn(auth: &str, hosts: &[&str]) -> MediaConn {
        MediaConn {
            auth: auth.to_string(),
            ttl: 60,
            hosts: hosts
                .iter()
                .map(|hostname| MediaConnHost {
                    hostname: (*hostname).to_string(),
                })
                .collect(),
            fetched_at: Instant::now(),
        }
    }

    #[tokio::test]
    async fn upload_retries_with_forced_media_conn_refresh_after_auth_error() {
        let enc = wacore::upload::encrypt_media(b"retry me", MediaType::Image)
            .expect("encryption should succeed");
        let first_conn = media_conn("stale-auth", &["cdn1.example.com"]);
        let refreshed_conn = media_conn("fresh-auth", &["cdn2.example.com"]);
        let refresh_calls = Arc::new(Mutex::new(Vec::new()));
        let invalidations = Arc::new(Mutex::new(0usize));
        let seen_urls = Arc::new(Mutex::new(Vec::new()));

        let result = upload_media_with_retry(
            &enc,
            MediaType::Image,
            8,
            {
                let refresh_calls = Arc::clone(&refresh_calls);
                move |force| {
                    let refresh_calls = Arc::clone(&refresh_calls);
                    let first_conn = first_conn.clone();
                    let refreshed_conn = refreshed_conn.clone();
                    async move {
                        refresh_calls.lock().await.push(force);
                        Ok(if force { refreshed_conn } else { first_conn })
                    }
                }
            },
            {
                let invalidations = Arc::clone(&invalidations);
                move || {
                    let invalidations = Arc::clone(&invalidations);
                    async move {
                        *invalidations.lock().await += 1;
                    }
                }
            },
            {
                let seen_urls = Arc::clone(&seen_urls);
                move |request| {
                    let seen_urls = Arc::clone(&seen_urls);
                    async move {
                        seen_urls.lock().await.push(request.url.clone());
                        if request.url.contains("stale-auth") {
                            Ok(HttpResponse {
                                status_code: 401,
                                body: b"expired".to_vec(),
                            })
                        } else {
                            Ok(HttpResponse {
                                status_code: 200,
                                body: br#"{"url":"https://cdn2.example.com/file","direct_path":"/v/t62.7118-24/123"}"#.to_vec(),
                            })
                        }
                    }
                }
            },
        )
        .await
        .expect("upload should succeed after refreshing media auth");

        assert_eq!(*refresh_calls.lock().await, vec![false, true]);
        assert_eq!(*invalidations.lock().await, 1);

        let seen_urls = seen_urls.lock().await.clone();
        assert_eq!(seen_urls.len(), 2);
        assert!(seen_urls[0].contains("cdn1.example.com"));
        assert!(seen_urls[0].contains("auth=stale-auth"));
        assert!(seen_urls[1].contains("cdn2.example.com"));
        assert!(seen_urls[1].contains("auth=fresh-auth"));
        assert_eq!(result.direct_path, "/v/t62.7118-24/123");
        assert_eq!(result.url, "https://cdn2.example.com/file");
    }

    #[tokio::test]
    async fn upload_fails_over_to_next_host_after_non_auth_error() {
        let enc = wacore::upload::encrypt_media(b"retry host", MediaType::Image)
            .expect("encryption should succeed");
        let conn = media_conn("shared-auth", &["cdn1.example.com", "cdn2.example.com"]);
        let seen_urls = Arc::new(Mutex::new(Vec::new()));

        let result = upload_media_with_retry(
            &enc,
            MediaType::Image,
            10,
            move |_force| {
                let conn = conn.clone();
                async move { Ok(conn) }
            },
            || async {},
            {
                let seen_urls = Arc::clone(&seen_urls);
                move |request| {
                    let seen_urls = Arc::clone(&seen_urls);
                    async move {
                        seen_urls.lock().await.push(request.url.clone());
                        if request.url.contains("cdn1.example.com") {
                            Ok(HttpResponse {
                                status_code: 500,
                                body: b"try another host".to_vec(),
                            })
                        } else {
                            Ok(HttpResponse {
                                status_code: 200,
                                body: br#"{"url":"https://cdn2.example.com/file","direct_path":"/v/t62.7118-24/456"}"#.to_vec(),
                            })
                        }
                    }
                }
            },
        )
        .await
        .expect("upload should succeed on the second host");

        let seen_urls = seen_urls.lock().await.clone();
        assert_eq!(seen_urls.len(), 2);
        assert!(seen_urls[0].contains("cdn1.example.com"));
        assert!(seen_urls[1].contains("cdn2.example.com"));
        assert_eq!(result.direct_path, "/v/t62.7118-24/456");
    }
}
