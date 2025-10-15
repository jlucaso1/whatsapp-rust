use anyhow::Result;
use async_trait::async_trait;
use std::io::Read;
use wacore::net::{HttpClient, HttpRequest, HttpResponse};

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

            // Extract the body and convert it to a reader.
            // Body::into_reader() returns a BodyReader which implements std::io::Read.
            // This avoids loading the entire response into memory at once.
            let body: Box<dyn Read + Send + Sync> = Box::new(response.into_body().into_reader());

            Ok(HttpResponse { status_code, body })
        })
        .await?
    }
}
