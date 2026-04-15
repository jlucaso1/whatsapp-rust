use crate::request::InfoQuery;

/// A reusable IQ specification that pairs a request builder with a response parser.
///
/// This keeps protocol-level IQ logic in `wacore`, while runtime orchestration
/// (sending, retries, timeouts) stays in the main crate.
pub trait IqSpec {
    /// The output type produced by parsing the IQ response.
    type Response;

    /// Build the IQ stanza for this spec.
    fn build_iq(&self) -> InfoQuery<'static>;

    /// Optionally encode the IQ stanza directly into a pre-sized buffer,
    /// bypassing the Node intermediate representation. Returns `true` if
    /// the fast path was used; `false` falls back to `build_iq()` + marshal.
    ///
    /// The buffer must contain the full binary-encoded `<iq>` stanza including
    /// the leading format byte. `request_id` is the IQ request ID.
    fn encode_iq_direct(
        &self,
        _request_id: &str,
        _out: &mut Vec<u8>,
    ) -> Result<bool, anyhow::Error> {
        Ok(false)
    }

    /// Parse the IQ response node into the typed response.
    fn parse_response(
        &self,
        response: &wacore_binary::NodeRef<'_>,
    ) -> Result<Self::Response, anyhow::Error>;
}
