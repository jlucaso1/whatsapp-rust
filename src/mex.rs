use crate::client::Client;
use crate::request::{InfoQuery, InfoQueryType, IqError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use wacore_binary::{builder::NodeBuilder, jid::SERVER_JID, node::NodeContent};

#[derive(Debug, Deserialize)]
pub struct GraphQLErrorExtensions {
    pub error_code: Option<i64>,
    pub is_retryable: Option<bool>,
    pub severity: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GraphQLError {
    pub extensions: Option<GraphQLErrorExtensions>,
    pub message: String,
    pub path: Option<Vec<String>>,
}

impl fmt::Display for GraphQLError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ext) = &self.extensions {
            write!(
                f,
                "GraphQL Error (code: {:?}): {}",
                ext.error_code, self.message
            )
        } else {
            write!(f, "GraphQL Error: {}", self.message)
        }
    }
}

impl std::error::Error for GraphQLError {}

#[derive(Debug, Deserialize)]
pub struct GraphQLResponse {
    pub data: Value,
    #[serde(default)]
    pub errors: Vec<GraphQLError>,
}

impl Client {
    pub async fn send_mex_query(
        &self,
        query_id: &str,
        variables: impl Serialize,
    ) -> Result<Value, anyhow::Error> {
        #[derive(Serialize)]
        struct MexPayload<T: Serialize> {
            variables: T,
        }

        let payload = MexPayload { variables };
        let payload_bytes = serde_json::to_vec(&payload)?;

        let query_node = NodeBuilder::new("query")
            .attr("query_id", query_id)
            .bytes(payload_bytes)
            .build();

        let iq = InfoQuery {
            namespace: "w:mex",
            query_type: InfoQueryType::Get,
            to: SERVER_JID.parse().unwrap(),
            content: Some(NodeContent::Nodes(vec![query_node])),
            id: None,
            target: None,
            timeout: None,
        };

        let resp_node = self.send_iq(iq).await?;

        let result_node =
            resp_node
                .get_optional_child("result")
                .ok_or_else(|| IqError::ServerError {
                    code: 500,
                    text: "Missing <result> node in mex response".to_string(),
                })?;

        let result_bytes = match result_node.content.as_ref() {
            Some(NodeContent::Bytes(bytes)) => bytes,
            _ => {
                return Err(anyhow::anyhow!("mex <result> node content is not bytes"));
            }
        };

        let gql_resp: GraphQLResponse = serde_json::from_slice(result_bytes)?;

        if !gql_resp.errors.is_empty() {
            let error_messages: Vec<String> =
                gql_resp.errors.iter().map(|e| e.to_string()).collect();
            return Err(anyhow::anyhow!(
                "GraphQL query failed: {}",
                error_messages.join(", ")
            ));
        }

        Ok(gql_resp.data)
    }
}
