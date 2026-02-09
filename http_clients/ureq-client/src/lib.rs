use anyhow::Result;
use async_trait::async_trait;
use wacore::net::{HttpClient, HttpRequest, HttpResponse, StreamingHttpResponse};

/// HTTP client implementation using `ureq` for synchronous HTTP requests.
/// Since `ureq` is blocking, all requests are wrapped in `tokio::task::spawn_blocking`.
#[derive(Debug, Clone)]
pub struct UreqHttpClient;

impl UreqHttpClient {
    pub fn new() -> Self {
        Self
    }
}

impl Default for UreqHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HttpClient for UreqHttpClient {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse> {
        // Since ureq is blocking, we must use spawn_blocking
        tokio::task::spawn_blocking(move || {
            let response = match request.method.as_str() {
                "GET" => {
                    let mut req = ureq::get(&request.url);
                    for (key, value) in &request.headers {
                        req = req.header(key, value);
                    }
                    req.call()?
                }
                "POST" => {
                    let mut req = ureq::post(&request.url);
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

            // Read the response body
            let mut body = response.into_body();
            let body_bytes = body.read_to_vec()?;

            Ok(HttpResponse {
                status_code,
                body: body_bytes,
            })
        })
        .await?
    }

    fn execute_streaming(&self, request: HttpRequest) -> Result<StreamingHttpResponse> {
        // Note: no spawn_blocking here — this is called FROM within spawn_blocking
        // by the streaming download code. The entire HTTP fetch + decrypt happens
        // in one blocking thread.
        let response = match request.method.as_str() {
            "GET" => {
                let mut req = ureq::get(&request.url);
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
