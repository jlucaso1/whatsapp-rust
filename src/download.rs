use crate::client::Client;
use crate::mediaconn::{MEDIA_AUTH_REFRESH_RETRY_ATTEMPTS, MediaConn, is_media_auth_error};
use anyhow::{Result, anyhow};
use std::io::{Seek, SeekFrom, Write};

pub use wacore::download::{
    DownloadUtils, Downloadable, MediaDecryption, MediaDecryptionError, MediaType,
};

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

#[derive(Debug)]
enum DownloadRequestError {
    Auth(anyhow::Error),
    /// 404/410 — media URL expired or not found. Needs fresh auth + URL re-derivation.
    /// Matches WA Web's `MediaNotFoundError` handling.
    NotFound(anyhow::Error),
    Other(anyhow::Error),
}

impl DownloadRequestError {
    fn auth(status_code: u16) -> Self {
        Self::Auth(anyhow!("Download failed with status: {}", status_code))
    }

    fn not_found(status_code: u16) -> Self {
        Self::NotFound(anyhow!(
            "Download media not found/expired with status: {}",
            status_code
        ))
    }

    fn other(err: impl Into<anyhow::Error>) -> Self {
        Self::Other(err.into())
    }

    fn is_auth(&self) -> bool {
        matches!(self, Self::Auth(_))
    }

    /// Returns true for 404/410 (expired URL) — should trigger auth refresh like auth errors.
    fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound(_))
    }

    fn into_anyhow(self) -> anyhow::Error {
        match self {
            Self::Auth(err) | Self::NotFound(err) | Self::Other(err) => err,
        }
    }
}

async fn download_media_with_retry<
    PrepareRequests,
    PrepareRequestsFut,
    InvalidateMediaConn,
    InvalidateMediaConnFut,
    ExecuteRequest,
    ExecuteRequestFut,
>(
    mut prepare_requests: PrepareRequests,
    mut invalidate_media_conn: InvalidateMediaConn,
    mut execute_request: ExecuteRequest,
) -> Result<Vec<u8>>
where
    PrepareRequests: FnMut(bool) -> PrepareRequestsFut,
    PrepareRequestsFut:
        std::future::Future<Output = Result<Vec<wacore::download::DownloadRequest>>>,
    InvalidateMediaConn: FnMut() -> InvalidateMediaConnFut,
    InvalidateMediaConnFut: std::future::Future<Output = ()>,
    ExecuteRequest: FnMut(wacore::download::DownloadRequest) -> ExecuteRequestFut,
    ExecuteRequestFut:
        std::future::Future<Output = std::result::Result<Vec<u8>, DownloadRequestError>>,
{
    let mut force_refresh = false;
    let mut last_err: Option<anyhow::Error> = None;

    for attempt in 0..=MEDIA_AUTH_REFRESH_RETRY_ATTEMPTS {
        let requests = prepare_requests(force_refresh).await?;
        let mut retry_with_fresh_auth = false;

        for request in requests {
            match execute_request(request.clone()).await {
                Ok(data) => return Ok(data),
                Err(err) if (err.is_auth() || err.is_not_found()) && attempt == 0 => {
                    // Auth error or 404/410 (expired URL): refresh media conn and re-derive URLs.
                    // Matches WA Web's MediaNotFoundError → forceRefresh flow.
                    invalidate_media_conn().await;
                    force_refresh = true;
                    retry_with_fresh_auth = true;
                    break;
                }
                Err(err) if err.is_auth() || err.is_not_found() => return Err(err.into_anyhow()),
                Err(err) => {
                    let err = err.into_anyhow();
                    log::warn!(
                        "Failed to download from URL {}: {:?}. Trying next host.",
                        request.url,
                        err
                    );
                    last_err = Some(err);
                }
            }
        }

        if !retry_with_fresh_auth {
            break;
        }
    }

    match last_err {
        Some(err) => Err(err),
        None => Err(anyhow!("Failed to download from all available media hosts")),
    }
}

async fn download_to_writer_with_retry<
    W,
    PrepareRequests,
    PrepareRequestsFut,
    InvalidateMediaConn,
    InvalidateMediaConnFut,
    ExecuteRequest,
    ExecuteRequestFut,
>(
    mut writer: W,
    mut prepare_requests: PrepareRequests,
    mut invalidate_media_conn: InvalidateMediaConn,
    mut execute_request: ExecuteRequest,
) -> Result<W>
where
    W: Write + Seek + Send + 'static,
    PrepareRequests: FnMut(bool) -> PrepareRequestsFut,
    PrepareRequestsFut:
        std::future::Future<Output = Result<Vec<wacore::download::DownloadRequest>>>,
    InvalidateMediaConn: FnMut() -> InvalidateMediaConnFut,
    InvalidateMediaConnFut: std::future::Future<Output = ()>,
    ExecuteRequest: FnMut(wacore::download::DownloadRequest, W) -> ExecuteRequestFut,
    ExecuteRequestFut:
        std::future::Future<Output = Result<(W, std::result::Result<(), DownloadRequestError>)>>,
{
    let mut force_refresh = false;
    let mut last_err: Option<anyhow::Error> = None;

    for attempt in 0..=MEDIA_AUTH_REFRESH_RETRY_ATTEMPTS {
        let requests = prepare_requests(force_refresh).await?;
        let mut retry_with_fresh_auth = false;

        for request in requests {
            let (next_writer, result) = execute_request(request.clone(), writer).await?;
            writer = next_writer;

            match result {
                Ok(()) => return Ok(writer),
                Err(err) if (err.is_auth() || err.is_not_found()) && attempt == 0 => {
                    invalidate_media_conn().await;
                    force_refresh = true;
                    retry_with_fresh_auth = true;
                    break;
                }
                Err(err) if err.is_auth() || err.is_not_found() => return Err(err.into_anyhow()),
                Err(err) => {
                    let err = err.into_anyhow();
                    log::warn!(
                        "Failed to stream-download from URL {}: {:?}. Trying next host.",
                        request.url,
                        err
                    );
                    last_err = Some(err);
                }
            }
        }

        if !retry_with_fresh_auth {
            break;
        }
    }

    match last_err {
        Some(err) => Err(err),
        None => Err(anyhow!("Failed to download from all available media hosts")),
    }
}

impl Client {
    pub async fn download(&self, downloadable: &dyn Downloadable) -> Result<Vec<u8>> {
        download_media_with_retry(
            |force| self.prepare_requests(downloadable, force),
            || async { self.invalidate_media_conn().await },
            |request| async move { self.download_with_request(&request).await },
        )
        .await
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
        force_refresh: bool,
    ) -> Result<Vec<wacore::download::DownloadRequest>> {
        let media_conn = self.refresh_media_conn(force_refresh).await?;
        let core_media_conn = wacore::download::MediaConnection::from(&media_conn);
        DownloadUtils::prepare_download_requests(downloadable, &core_media_conn)
    }

    async fn download_with_request(
        &self,
        request: &wacore::download::DownloadRequest,
    ) -> std::result::Result<Vec<u8>, DownloadRequestError> {
        let url = request.url.clone();
        let decryption = request.decryption.clone();
        let http_request = crate::http::HttpRequest::get(url);
        let response = self
            .http_client
            .execute(http_request)
            .await
            .map_err(DownloadRequestError::other)?;

        if response.status_code >= 300 {
            return Err(if is_media_auth_error(response.status_code) {
                DownloadRequestError::auth(response.status_code)
            } else if matches!(response.status_code, 404 | 410) {
                DownloadRequestError::not_found(response.status_code)
            } else {
                DownloadRequestError::other(anyhow!(
                    "Download failed with status: {}",
                    response.status_code
                ))
            });
        }

        match decryption {
            MediaDecryption::Encrypted {
                media_key,
                media_type,
            } => wacore::runtime::blocking(&*self.runtime, move || {
                DownloadUtils::decrypt_stream(&response.body[..], &media_key, media_type)
            })
            .await
            .map_err(DownloadRequestError::other),
            MediaDecryption::Plaintext { file_sha256 } => {
                let body = response.body;
                wacore::runtime::blocking(&*self.runtime, move || {
                    DownloadUtils::validate_plaintext_sha256(&body, &file_sha256)?;
                    Ok::<Vec<u8>, anyhow::Error>(body)
                })
                .await
                .map_err(DownloadRequestError::other)
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
        download_to_writer_with_retry(
            writer,
            |force| self.prepare_requests(downloadable, force),
            || async { self.invalidate_media_conn().await },
            |request, writer| async move { self.streaming_download_and_decrypt(&request, writer).await },
        )
        .await
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
    ) -> Result<(W, std::result::Result<(), DownloadRequestError>)> {
        let http_client = self.http_client.clone();
        let url = request.url.clone();
        let decryption = request.decryption.clone();

        wacore::runtime::blocking(&*self.runtime, move || {
            let mut writer = writer;

            // Seek to start before each attempt so retries start fresh
            if let Err(e) = writer.seek(SeekFrom::Start(0)) {
                return Ok((writer, Err(DownloadRequestError::other(e))));
            }

            let result = (|| -> std::result::Result<(), DownloadRequestError> {
                let http_request = crate::http::HttpRequest::get(url);
                let resp = http_client
                    .execute_streaming(http_request)
                    .map_err(DownloadRequestError::other)?;

                if resp.status_code >= 300 {
                    return Err(if is_media_auth_error(resp.status_code) {
                        DownloadRequestError::auth(resp.status_code)
                    } else if matches!(resp.status_code, 404 | 410) {
                        DownloadRequestError::not_found(resp.status_code)
                    } else {
                        DownloadRequestError::other(anyhow!(
                            "Download failed with status: {}",
                            resp.status_code
                        ))
                    });
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
                        )
                        .map_err(DownloadRequestError::other)?;
                    }
                    MediaDecryption::Plaintext { file_sha256 } => {
                        DownloadUtils::copy_and_validate_plaintext_to_writer(
                            resp.body,
                            file_sha256,
                            &mut writer,
                        )
                        .map_err(DownloadRequestError::other)?;
                    }
                }
                writer
                    .seek(SeekFrom::Start(0))
                    .map_err(DownloadRequestError::other)?;
                Ok(())
            })();

            Ok((writer, result))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediaconn::{MediaConn, MediaConnHost};
    use async_lock::Mutex;
    use std::io::Cursor;
    use std::sync::Arc;
    use wacore::time::Instant;

    struct PlaintextDownloadable {
        direct_path: String,
        file_sha256: Vec<u8>,
    }

    impl Downloadable for PlaintextDownloadable {
        fn direct_path(&self) -> Option<&str> {
            Some(&self.direct_path)
        }

        fn media_key(&self) -> Option<&[u8]> {
            None
        }

        fn file_enc_sha256(&self) -> Option<&[u8]> {
            None
        }

        fn file_sha256(&self) -> Option<&[u8]> {
            Some(&self.file_sha256)
        }

        fn file_length(&self) -> Option<u64> {
            None
        }

        fn app_info(&self) -> MediaType {
            MediaType::Image
        }
    }

    fn media_conn(auth: &str, hosts: &[&str]) -> MediaConn {
        MediaConn {
            auth: auth.to_string(),
            ttl: 60,
            auth_ttl: None,
            hosts: hosts
                .iter()
                .map(|hostname| MediaConnHost::new((*hostname).to_string()))
                .collect(),
            fetched_at: Instant::now(),
        }
    }

    fn plaintext_sha256(data: &[u8]) -> Vec<u8> {
        wacore::upload::encrypt_media(data, MediaType::Image)
            .expect("hash derivation should succeed")
            .file_sha256
            .to_vec()
    }

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

        assert!(
            matches!(&err, wacore::download::MediaDecryptionError::InvalidMac),
            "Expected InvalidMac, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn download_retries_with_forced_media_conn_refresh_after_auth_error() {
        let body = b"download me".to_vec();
        let downloadable = PlaintextDownloadable {
            direct_path: "/v/t62.7118-24/123".to_string(),
            file_sha256: plaintext_sha256(&body),
        };
        let first_conn = media_conn("stale-auth", &["cdn1.example.com"]);
        let refreshed_conn = media_conn("fresh-auth", &["cdn2.example.com"]);
        let refresh_calls = Arc::new(Mutex::new(Vec::new()));
        let invalidations = Arc::new(Mutex::new(0usize));
        let seen_urls = Arc::new(Mutex::new(Vec::new()));

        let downloaded = download_media_with_retry(
            {
                let refresh_calls = Arc::clone(&refresh_calls);
                let downloadable = &downloadable;
                move |force| {
                    let refresh_calls = Arc::clone(&refresh_calls);
                    let first_conn = first_conn.clone();
                    let refreshed_conn = refreshed_conn.clone();
                    async move {
                        refresh_calls.lock().await.push(force);
                        let media_conn = if force { refreshed_conn } else { first_conn };
                        DownloadUtils::prepare_download_requests(
                            downloadable,
                            &wacore::download::MediaConnection::from(&media_conn),
                        )
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
                let body = body.clone();
                move |request| {
                    let seen_urls = Arc::clone(&seen_urls);
                    let body = body.clone();
                    let url = request.url.clone();
                    async move {
                        seen_urls.lock().await.push(url.clone());
                        if url.contains("stale-auth") {
                            Err(DownloadRequestError::auth(401))
                        } else {
                            Ok(body)
                        }
                    }
                }
            },
        )
        .await
        .expect("download should succeed after refreshing media auth");

        assert_eq!(downloaded, body);
        assert_eq!(*refresh_calls.lock().await, vec![false, true]);
        assert_eq!(*invalidations.lock().await, 1);

        let seen_urls = seen_urls.lock().await.clone();
        assert_eq!(seen_urls.len(), 2);
        assert!(seen_urls[0].contains("auth=stale-auth"));
        assert!(seen_urls[1].contains("auth=fresh-auth"));
    }

    #[tokio::test]
    async fn download_to_writer_retries_with_forced_media_conn_refresh_after_auth_error() {
        let body = b"stream me".to_vec();
        let downloadable = PlaintextDownloadable {
            direct_path: "/v/t62.7118-24/stream".to_string(),
            file_sha256: plaintext_sha256(&body),
        };
        let first_conn = media_conn("stale-auth", &["cdn1.example.com"]);
        let refreshed_conn = media_conn("fresh-auth", &["cdn2.example.com"]);
        let refresh_calls = Arc::new(Mutex::new(Vec::new()));
        let invalidations = Arc::new(Mutex::new(0usize));
        let seen_urls = Arc::new(Mutex::new(Vec::new()));

        let writer = download_to_writer_with_retry(
            Cursor::new(Vec::<u8>::new()),
            {
                let refresh_calls = Arc::clone(&refresh_calls);
                let downloadable = &downloadable;
                move |force| {
                    let refresh_calls = Arc::clone(&refresh_calls);
                    let first_conn = first_conn.clone();
                    let refreshed_conn = refreshed_conn.clone();
                    async move {
                        refresh_calls.lock().await.push(force);
                        let media_conn = if force { refreshed_conn } else { first_conn };
                        DownloadUtils::prepare_download_requests(
                            downloadable,
                            &wacore::download::MediaConnection::from(&media_conn),
                        )
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
                let body = body.clone();
                move |request, mut writer| {
                    let seen_urls = Arc::clone(&seen_urls);
                    let body = body.clone();
                    let url = request.url.clone();
                    async move {
                        seen_urls.lock().await.push(url.clone());
                        writer.seek(SeekFrom::Start(0))?;
                        if url.contains("stale-auth") {
                            Ok((writer, Err(DownloadRequestError::auth(403))))
                        } else {
                            writer.write_all(&body)?;
                            writer.seek(SeekFrom::Start(0))?;
                            Ok((writer, Ok(())))
                        }
                    }
                }
            },
        )
        .await
        .expect("streaming download should succeed after refreshing media auth");

        assert_eq!(writer.into_inner(), body);
        assert_eq!(*refresh_calls.lock().await, vec![false, true]);
        assert_eq!(*invalidations.lock().await, 1);

        let seen_urls = seen_urls.lock().await.clone();
        assert_eq!(seen_urls.len(), 2);
        assert!(seen_urls[0].contains("auth=stale-auth"));
        assert!(seen_urls[1].contains("auth=fresh-auth"));
    }
}
