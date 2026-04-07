use crate::request::InfoQuery;
use wacore_binary::node::Node;

/// A reusable IQ specification that pairs a request builder with a response parser.
///
/// This keeps protocol-level IQ logic in `wacore`, while runtime orchestration
/// (sending, retries, timeouts) stays in the main crate.
pub trait IqSpec {
    /// The output type produced by parsing the IQ response.
    type Response;

    /// Build the IQ stanza for this spec.
    fn build_iq(&self) -> InfoQuery<'static>;

    /// Parse the IQ response node into the typed response.
    fn parse_response(&self, response: &Node) -> Result<Self::Response, anyhow::Error>;
}
