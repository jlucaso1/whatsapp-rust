// ureq is a blocking HTTP client that depends on std::net and OS threads.
// It cannot work on wasm32 targets — users must provide their own HttpClient.
#![cfg(not(target_arch = "wasm32"))]

use anyhow::Result;
use async_trait::async_trait;
use wacore::net::{HttpClient, HttpRequest, HttpResponse, StreamingHttpResponse};

/// Matches `MAX_FILE_SIZE_BYTES` in `WAWebServerPropConstants` (2 GiB).
/// Overrides ureq's 10 MiB default on `read_to_vec()`.
pub const DEFAULT_MAX_BODY_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// HTTP client implementation using `ureq` for synchronous HTTP requests.
/// Since `ureq` is blocking, all requests are wrapped in `tokio::task::spawn_blocking`.
#[derive(Debug, Clone)]
pub struct UreqHttpClient {
    agent: ureq::Agent,
    /// Cap for [`UreqHttpClient::execute`]. Streaming is unbounded — the
    /// caller owns the sink.
    max_body_bytes: u64,
}

impl UreqHttpClient {
    pub fn new() -> Self {
        Self {
            agent: build_agent(),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }

    /// Create a client with a pre-configured [`ureq::Agent`].
    ///
    /// This lets you configure proxy support, custom TLS, timeouts,
    /// or any other agent-level settings externally.
    pub fn with_agent(agent: ureq::Agent) -> Self {
        Self {
            agent,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }

    /// Override the per-response cap for [`UreqHttpClient::execute`]. Set to
    /// `u64::MAX` to disable; a hostile server can then exhaust memory.
    pub fn with_max_body_bytes(mut self, max_body_bytes: u64) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }
}

impl Default for UreqHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

fn build_agent() -> ureq::Agent {
    use ureq::config::Config;

    #[allow(unused_mut)]
    let mut builder = Config::builder()
        // 16 KB per buffer instead of the 128 KB default.
        // WA API payloads are small JSON; media uses streaming I/O.
        .input_buffer_size(16 * 1024)
        .output_buffer_size(16 * 1024)
        .max_idle_connections(3)
        .max_idle_connections_per_host(2);

    #[cfg(feature = "danger-skip-tls-verify")]
    {
        use ureq::tls::TlsConfig;
        builder = builder.tls_config(TlsConfig::builder().disable_verification(true).build());
    }

    builder.build().into()
}

#[async_trait]
impl HttpClient for UreqHttpClient {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse> {
        let agent = self.agent.clone();
        let max_body_bytes = self.max_body_bytes;
        // Since ureq is blocking, we must use spawn_blocking
        tokio::task::spawn_blocking(move || {
            let response = match request.method.as_str() {
                "GET" => {
                    let mut req = agent.get(&request.url);
                    for (key, value) in &request.headers {
                        req = req.header(key, value);
                    }
                    req.call()?
                }
                "POST" => {
                    let mut req = agent.post(&request.url);
                    for (key, value) in &request.headers {
                        req = req.header(key, value);
                    }
                    if let Some(body) = request.body {
                        req.send(&body[..])?
                    } else {
                        req.send(&[])?
                    }
                }
                method => {
                    return Err(anyhow::anyhow!("Unsupported HTTP method: {}", method));
                }
            };

            let status_code = response.status().as_u16();

            // ureq's `read_to_vec()` default cap is 10 MiB.
            let body_bytes = response
                .into_body()
                .into_with_config()
                .limit(max_body_bytes)
                .read_to_vec()?;

            Ok(HttpResponse {
                status_code,
                body: body_bytes,
            })
        })
        .await?
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn execute_streaming(&self, request: HttpRequest) -> Result<StreamingHttpResponse> {
        // Note: no spawn_blocking here — this is called FROM within spawn_blocking
        // by the streaming download code. The entire HTTP fetch + decrypt happens
        // in one blocking thread.
        let response = match request.method.as_str() {
            "GET" => {
                let mut req = self.agent.get(&request.url);
                for (key, value) in &request.headers {
                    req = req.header(key, value);
                }
                req.call()?
            }
            method => {
                return Err(anyhow::anyhow!(
                    "Streaming only supports GET, got: {}",
                    method
                ));
            }
        };

        let status_code = response.status().as_u16();
        let reader = response.into_body().into_reader();

        Ok(StreamingHttpResponse {
            status_code,
            body: Box::new(reader),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn spawn_fixed_size_server(body_size: usize) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 4096];
            let mut total = Vec::new();
            loop {
                let n = stream.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    return;
                }
                total.extend_from_slice(&buf[..n]);
                if total.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body_size
            );
            stream.write_all(header.as_bytes()).unwrap();
            let chunk = vec![0xABu8; 64 * 1024];
            let mut sent = 0usize;
            while sent < body_size {
                let take = chunk.len().min(body_size - sent);
                stream.write_all(&chunk[..take]).unwrap();
                sent += take;
            }
        });
        format!("http://{}", addr)
    }

    /// Regression: ureq 3.x caps `read_to_vec()` at 10 MiB by default.
    #[tokio::test(flavor = "current_thread")]
    async fn execute_accepts_body_larger_than_ureq_default_limit() {
        const SIZE: usize = 12 * 1024 * 1024;
        let url = spawn_fixed_size_server(SIZE);
        let resp = UreqHttpClient::new()
            .execute(HttpRequest {
                method: "GET".into(),
                url,
                headers: std::collections::HashMap::new(),
                body: None,
            })
            .await
            .expect("body must fit under the configured cap");
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.body.len(), SIZE);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn with_max_body_bytes_enforces_tighter_cap() {
        const SIZE: usize = 4 * 1024 * 1024;
        let url = spawn_fixed_size_server(SIZE);
        UreqHttpClient::new()
            .with_max_body_bytes(1024)
            .execute(HttpRequest {
                method: "GET".into(),
                url,
                headers: std::collections::HashMap::new(),
                body: None,
            })
            .await
            .expect_err("1 KiB cap must reject a 4 MiB body");
    }
}
