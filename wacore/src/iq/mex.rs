//! MEX (Meta Exchange) GraphQL IQ specification.
//!
//! MEX is WhatsApp's GraphQL API for querying user data, contact information,
//! and other Meta-related services.
//!
//! Wire format:
//! ```xml
//! <!-- Request -->
//! <iq xmlns="w:mex" type="get" to="s.whatsapp.net" id="...">
//!   <query query_id="29829202653362039">{"variables":{...}}</query>
//! </iq>
//!
//! <!-- Response -->
//! <iq from="s.whatsapp.net" id="..." type="result">
//!   <result>{"data":{...},"errors":[...]}</result>
//! </iq>
//! ```

use crate::iq::spec::IqSpec;
use crate::request::InfoQuery;
use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::{Node, NodeContent};

/// MEX GraphQL error extensions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MexErrorExtensions {
    pub error_code: Option<i32>,
    pub is_summary: Option<bool>,
    pub is_retryable: Option<bool>,
    pub severity: Option<String>,
}

/// MEX GraphQL error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MexGraphQLError {
    pub message: String,
    pub extensions: Option<MexErrorExtensions>,
}

impl MexGraphQLError {
    #[inline]
    pub fn error_code(&self) -> Option<i32> {
        self.extensions.as_ref()?.error_code
    }

    #[inline]
    pub fn is_fatal(&self) -> bool {
        self.extensions
            .as_ref()
            .is_some_and(|ext| ext.is_summary == Some(true))
    }
}

/// MEX GraphQL response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MexResponse {
    pub data: Option<Value>,
    pub errors: Option<Vec<MexGraphQLError>>,
}

impl MexResponse {
    #[inline]
    pub fn has_data(&self) -> bool {
        self.data.is_some()
    }

    #[inline]
    pub fn has_errors(&self) -> bool {
        self.errors.as_ref().is_some_and(|e| !e.is_empty())
    }

    pub fn fatal_error(&self) -> Option<&MexGraphQLError> {
        self.errors.as_ref()?.iter().find(|e| e.is_fatal())
    }
}

#[derive(Serialize)]
struct MexPayload<'a> {
    variables: &'a Value,
}

/// MEX GraphQL query IQ specification.
#[derive(Debug, Clone)]
pub struct MexQuerySpec {
    pub doc_id: String,
    pub variables: Value,
}

impl MexQuerySpec {
    pub fn new(doc_id: impl Into<String>, variables: Value) -> Self {
        Self {
            doc_id: doc_id.into(),
            variables,
        }
    }
}

impl IqSpec for MexQuerySpec {
    type Response = MexResponse;

    fn build_iq(&self) -> InfoQuery<'static> {
        let payload = MexPayload {
            variables: &self.variables,
        };
        // Safety: MexPayload wraps &serde_json::Value, and serde_json::to_vec
        // cannot fail for Value (no custom serializers or non-string map keys).
        let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();

        let query_node = NodeBuilder::new("query")
            .attr("query_id", &self.doc_id)
            .bytes(payload_bytes)
            .build();

        InfoQuery::get(
            "w:mex",
            Jid::new("", SERVER_JID),
            Some(NodeContent::Nodes(vec![query_node])),
        )
    }

    fn parse_response(&self, response: &Node) -> Result<Self::Response, anyhow::Error> {
        let result_node = response
            .get_optional_child("result")
            .ok_or_else(|| anyhow!("Missing <result> node in MEX response"))?;

        // Handle both binary and string content from the server
        let mex_response: MexResponse = match &result_node.content {
            Some(NodeContent::Bytes(bytes)) => serde_json::from_slice(bytes)?,
            Some(NodeContent::String(s)) => serde_json::from_str(s)?,
            _ => return Err(anyhow!("MEX result node content is not binary or string")),
        };

        // Check for fatal errors
        if let Some(fatal) = mex_response.fatal_error() {
            let code = fatal.error_code().unwrap_or(500);
            return Err(anyhow!(
                "MEX fatal error (code={}): {}",
                code,
                fatal.message
            ));
        }

        Ok(mex_response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_mex_query_spec_build_iq() {
        let spec = MexQuerySpec::new(
            "29829202653362039",
            json!({
                "input": {"query_input": [{"jid": "1234@s.whatsapp.net"}]},
                "include_username": true
            }),
        );
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, "w:mex");
        assert_eq!(iq.query_type, crate::request::InfoQueryType::Get);
        assert!(iq.content.is_some());

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].tag, "query");
            assert_eq!(
                nodes[0].attrs.get("query_id").and_then(|s| s.as_str()),
                Some("29829202653362039")
            );
        } else {
            panic!("Expected NodeContent::Nodes");
        }
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
    fn test_mex_graphql_error_methods() {
        let error = MexGraphQLError {
            message: "Test error".to_string(),
            extensions: Some(MexErrorExtensions {
                error_code: Some(404),
                is_summary: Some(false),
                is_retryable: Some(true),
                severity: Some("WARNING".to_string()),
            }),
        };

        assert_eq!(error.error_code(), Some(404));
        assert!(!error.is_fatal());
    }
}
