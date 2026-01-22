//! MEX (Meta Exchange) GraphQL feature.
//!
//! Protocol types are defined in `wacore::iq::mex`.

use crate::client::Client;
use crate::request::IqError;
use serde_json::Value;
use thiserror::Error;
use wacore::iq::mex::MexQuerySpec;

// Re-export types from wacore
pub use wacore::iq::mex::{MexErrorExtensions, MexGraphQLError, MexResponse};

/// Error types for MEX operations.
#[derive(Debug, Error)]
pub enum MexError {
    #[error("MEX payload parsing error: {0}")]
    PayloadParsing(String),

    #[error("MEX extension error: code={code}, message='{message}'")]
    ExtensionError { code: i32, message: String },

    #[error("IQ request failed: {0}")]
    Request(#[from] IqError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// MEX request with document ID and variables.
#[derive(Debug, Clone)]
pub struct MexRequest<'a> {
    /// GraphQL document ID.
    pub doc_id: &'a str,
    /// Query variables.
    pub variables: Value,
}

/// Feature handle for MEX GraphQL operations.
pub struct Mex<'a> {
    client: &'a Client,
}

impl<'a> Mex<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Execute a GraphQL query.
    #[inline]
    pub async fn query(&self, request: MexRequest<'_>) -> Result<MexResponse, MexError> {
        self.execute_request(request).await
    }

    /// Execute a GraphQL mutation.
    #[inline]
    pub async fn mutate(&self, request: MexRequest<'_>) -> Result<MexResponse, MexError> {
        self.execute_request(request).await
    }

    async fn execute_request(&self, request: MexRequest<'_>) -> Result<MexResponse, MexError> {
        let spec = MexQuerySpec::new(request.doc_id, request.variables);

        let response = self.client.execute(spec).await?;

        // Check for fatal errors (the IqSpec already checks, but we want to return our error type)
        if let Some(fatal) = response.fatal_error() {
            let code = fatal.error_code().unwrap_or(500);
            return Err(MexError::ExtensionError {
                code,
                message: fatal.message.clone(),
            });
        }

        Ok(response)
    }
}

impl Client {
    #[inline]
    pub fn mex(&self) -> Mex<'_> {
        Mex::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_mex_request_borrows_doc_id() {
        let doc_id = "29829202653362039";
        let request = MexRequest {
            doc_id,
            variables: json!({}),
        };

        assert_eq!(request.doc_id, "29829202653362039");
    }

    #[test]
    fn test_mex_response_deserialization() {
        let json_str = r#"{
            "data": {
                "xwa2_fetch_wa_users": [
                    {"jid": "1234567890@s.whatsapp.net", "country_code": "1"}
                ]
            }
        }"#;

        let response: MexResponse = serde_json::from_str(json_str).unwrap();
        assert!(response.has_data());
        assert!(!response.has_errors());
        assert!(response.fatal_error().is_none());
    }

    #[test]
    fn test_mex_response_with_non_fatal_errors() {
        let json_str = r#"{
            "data": null,
            "errors": [
                {
                    "message": "User not found",
                    "extensions": {
                        "error_code": 404,
                        "is_summary": false,
                        "is_retryable": false,
                        "severity": "WARNING"
                    }
                }
            ]
        }"#;

        let response: MexResponse = serde_json::from_str(json_str).unwrap();
        assert!(!response.has_data());
        assert!(response.has_errors());
        assert!(response.fatal_error().is_none());

        let errors = response.errors.as_ref().unwrap();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].message, "User not found");
        assert_eq!(errors[0].error_code(), Some(404));
        assert!(!errors[0].is_fatal());
    }

    #[test]
    fn test_mex_response_with_fatal_error() {
        let json_str = r#"{
            "data": null,
            "errors": [
                {
                    "message": "Fatal server error",
                    "extensions": {
                        "error_code": 500,
                        "is_summary": true,
                        "severity": "CRITICAL"
                    }
                }
            ]
        }"#;

        let response: MexResponse = serde_json::from_str(json_str).unwrap();
        assert!(!response.has_data());
        assert!(response.has_errors());

        let fatal = response.fatal_error();
        assert!(fatal.is_some());

        let fatal = fatal.unwrap();
        assert_eq!(fatal.message, "Fatal server error");
        assert_eq!(fatal.error_code(), Some(500));
        assert!(fatal.is_fatal());
    }

    #[test]
    fn test_mex_response_real_world() {
        let json_str = r#"{
            "data": {
                "xwa2_fetch_wa_users": [
                    {
                        "__typename": "XWA2User",
                        "about_status_info": {
                            "__typename": "XWA2AboutStatus",
                            "text": "Hello",
                            "timestamp": "1766267670"
                        },
                        "country_code": "BR",
                        "id": null,
                        "jid": "559984726662@s.whatsapp.net",
                        "username_info": {
                            "__typename": "XWA2ResponseStatus",
                            "status": "EMPTY"
                        }
                    }
                ]
            }
        }"#;

        let response: MexResponse = serde_json::from_str(json_str).unwrap();
        assert!(response.has_data());
        assert!(!response.has_errors());

        let data = response.data.unwrap();
        let users = data["xwa2_fetch_wa_users"].as_array().unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0]["country_code"], "BR");
        assert_eq!(users[0]["jid"], "559984726662@s.whatsapp.net");
    }

    #[test]
    fn test_mex_error_extensions_all_fields() {
        let json_str = r#"{
            "error_code": 400,
            "is_summary": false,
            "is_retryable": true,
            "severity": "WARNING"
        }"#;

        let ext: MexErrorExtensions = serde_json::from_str(json_str).unwrap();
        assert_eq!(ext.error_code, Some(400));
        assert_eq!(ext.is_summary, Some(false));
        assert_eq!(ext.is_retryable, Some(true));
        assert_eq!(ext.severity, Some("WARNING".to_string()));
    }

    #[test]
    fn test_mex_error_extensions_minimal() {
        let json_str = r#"{}"#;

        let ext: MexErrorExtensions = serde_json::from_str(json_str).unwrap();
        assert!(ext.error_code.is_none());
        assert!(ext.is_summary.is_none());
        assert!(ext.is_retryable.is_none());
        assert!(ext.severity.is_none());
    }
}
