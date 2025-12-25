use crate::client::Client;
use crate::jid_utils::server_jid;
use crate::request::{InfoQuery, IqError};
use serde::Deserialize;
use std::time::{Duration, Instant};
use wacore_binary::builder::NodeBuilder;

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
    pub(crate) async fn refresh_media_conn(&self, force: bool) -> Result<MediaConn, IqError> {
        {
            let guard = self.media_conn.read().await;
            if !force
                && let Some(conn) = &*guard
                && !conn.is_expired()
            {
                return Ok(conn.clone());
            }
        }

        let resp = self
            .send_iq(InfoQuery::set(
                "w:m",
                server_jid(),
                Some(wacore_binary::node::NodeContent::Nodes(vec![
                    NodeBuilder::new("media_conn").build(),
                ])),
            ))
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

        let mut write_guard = self.media_conn.write().await;
        *write_guard = Some(new_conn.clone());

        Ok(new_conn)
    }
}
