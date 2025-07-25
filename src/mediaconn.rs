use crate::binary::node::Node;
use crate::client::Client;
use crate::request::{InfoQuery, InfoQueryType, IqError};
use crate::types::jid::SERVER_JID;
use serde::Deserialize;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Deserialize)]
pub struct MediaConnHost {
    pub hostname: String,
}

#[derive(Debug, Clone)]
pub struct MediaConn {
    pub auth: String,
    pub ttl: u64,
    pub hosts: Vec<MediaConnHost>,
    pub fetched_at: Instant,
}

impl MediaConn {
    pub fn is_expired(&self) -> bool {
        self.fetched_at.elapsed() > Duration::from_secs(self.ttl)
    }
}

impl Client {
    pub async fn refresh_media_conn(&self, force: bool) -> Result<MediaConn, IqError> {
        {
            let guard = self.media_conn.lock().await;
            if !force {
                if let Some(conn) = &*guard {
                    if !conn.is_expired() {
                        return Ok(conn.clone());
                    }
                }
            }
        }

        let resp = self
            .send_iq(InfoQuery {
                namespace: "w:m",
                query_type: InfoQueryType::Set,
                to: SERVER_JID.parse().unwrap(),
                target: None,
                id: None,
                content: Some(crate::binary::node::NodeContent::Nodes(vec![Node {
                    tag: "media_conn".to_string(),
                    attrs: Default::default(),
                    content: None,
                }])),
                timeout: None,
            })
            .await?;

        let media_conn_node =
            resp.get_optional_child("media_conn")
                .ok_or_else(|| IqError::ServerError {
                    code: 500,
                    text: "Missing media_conn node in response".to_string(),
                })?;

        let mut attrs = media_conn_node.attrs();
        let auth = attrs.string("auth");
        let ttl = attrs.optional_u64("ttl").unwrap_or(0);

        let mut hosts = Vec::new();
        for host_node in media_conn_node.get_children_by_tag("host") {
            hosts.push(MediaConnHost {
                hostname: host_node.attrs().string("hostname"),
            });
        }

        let new_conn = MediaConn {
            auth,
            ttl,
            hosts,
            fetched_at: Instant::now(),
        };

        *self.media_conn.lock().await = Some(new_conn.clone());

        Ok(new_conn)
    }
}
