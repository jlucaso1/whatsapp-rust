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
use log::warn;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::{Jid, Server};
use wacore_binary::{NodeContent, NodeContentRef, NodeRef};

/// MEX persisted-query descriptor. Pairing `name` with `id` lets diagnostics
/// surface a stable identifier when the numeric `id` rotates between WA Web
/// bundle releases. Constants live in [`crate::iq::mex_ids`].
#[derive(Debug, Clone, Copy)]
pub struct MexDoc {
    pub name: &'static str,
    pub id: &'static str,
}

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
    pub fn is_summary(&self) -> bool {
        self.extensions
            .as_ref()
            .is_some_and(|ext| ext.is_summary == Some(true))
    }

    #[inline]
    pub fn has_error_code(&self) -> bool {
        self.error_code().is_some()
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

    /// Find a fatal error, matching WhatsApp Web's `parseFatalExtensionError`:
    /// 1. Error with `is_summary == true`
    /// 2. OR any error with an `error_code`
    /// 3. OR the first error (assigned code 500)
    pub fn fatal_error(&self) -> Option<&MexGraphQLError> {
        let errors = self.errors.as_ref()?;
        if errors.is_empty() {
            return None;
        }
        errors
            .iter()
            .find(|e| e.is_summary())
            .or_else(|| errors.iter().find(|e| e.has_error_code()))
            .or_else(|| errors.first())
    }
}

#[derive(Serialize)]
struct MexPayload<'a> {
    variables: &'a Value,
}

/// MEX GraphQL query IQ specification.
#[derive(Debug, Clone)]
pub struct MexQuerySpec {
    pub doc: MexDoc,
    pub variables: Value,
}

impl MexQuerySpec {
    pub fn new(doc: MexDoc, variables: Value) -> Self {
        Self { doc, variables }
    }
}

/// Heuristic match on substrings Relay/Mex use when a persisted-query id is
/// unknown to the server. Permissive on purpose: a false positive only adds
/// an extra hint to the warn line.
fn looks_like_stale_persisted_query(error: &MexGraphQLError) -> bool {
    let msg = error.message.as_bytes();
    contains_ascii_ci(msg, b"doc_id")
        || contains_ascii_ci(msg, b"persisted query")
        || contains_ascii_ci(msg, b"document not found")
        || contains_ascii_ci(msg, b"unknown query")
}

/// Case-insensitive ASCII substring search. Avoids the `String` allocation
/// `str::to_lowercase` would do on every MEX failure.
fn contains_ascii_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w.iter().zip(needle).all(|(h, n)| h.eq_ignore_ascii_case(n)))
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
            .attr("query_id", self.doc.id)
            .bytes(payload_bytes)
            .build();

        InfoQuery::get(
            "w:mex",
            Jid::new("", Server::Pn),
            Some(NodeContent::Nodes(vec![query_node])),
        )
    }

    fn parse_response(&self, response: &NodeRef<'_>) -> Result<Self::Response, anyhow::Error> {
        let result_node = response
            .get_optional_child("result")
            .ok_or_else(|| anyhow!("Missing <result> node in MEX response"))?;

        // Handle both binary and string content from the server
        let mex_response: MexResponse = match result_node.content.as_deref() {
            Some(NodeContentRef::Bytes(bytes)) => serde_json::from_slice(bytes)?,
            Some(NodeContentRef::String(s)) => serde_json::from_str(s)?,
            _ => return Err(anyhow!("MEX result node content is not binary or string")),
        };

        if let Some(fatal) = mex_response.fatal_error() {
            if looks_like_stale_persisted_query(fatal) {
                warn!(
                    target: "Mex",
                    "MEX query '{}' (doc_id={}) looks like a stale persisted-query id: {}. \
                     Refresh the id from the latest WA Web bundle in wacore::iq::mex_ids.",
                    self.doc.name, self.doc.id, fatal.message
                );
            }
            let code = fatal.error_code().unwrap_or(500);
            return Err(anyhow!(
                "MEX fatal error (query={}, code={}): {}",
                self.doc.name,
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

    const TEST_DOC: MexDoc = MexDoc {
        name: "WAWebMexTestQuery",
        id: "29829202653362039",
    };

    #[test]
    fn test_mex_query_spec_build_iq() {
        let spec = MexQuerySpec::new(
            TEST_DOC,
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
            assert!(
                nodes[0]
                    .attrs
                    .get("query_id")
                    .is_some_and(|s| s == TEST_DOC.id)
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
        assert!(fatal.is_summary());
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
        assert!(!error.is_summary());
    }

    #[test]
    fn test_stale_persisted_query_heuristic() {
        let mk = |msg: &str| MexGraphQLError {
            message: msg.to_string(),
            extensions: None,
        };
        assert!(looks_like_stale_persisted_query(&mk(
            "PersistedQuery `doc_id` 1234 not found"
        )));
        assert!(looks_like_stale_persisted_query(&mk(
            "Persisted query not registered"
        )));
        assert!(looks_like_stale_persisted_query(&mk(
            "Document not found for id"
        )));
        assert!(looks_like_stale_persisted_query(&mk(
            "Unknown query identifier"
        )));
        assert!(!looks_like_stale_persisted_query(&mk(
            "Group does not exist"
        )));
    }
}
