// Re-export HTTP client types from the ureq-client crate
// This allows the main crate to use the trait without creating a cyclic dependency
pub use whatsapp_rust_ureq_http_client::{HttpClient, HttpRequest, HttpResponse};
