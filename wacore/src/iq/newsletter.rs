//! Newsletter (Channel) IQ specifications.
//!
//! Newsletters use two protocol layers:
//! - Mex (GraphQL) for metadata/management operations — see
//!   `crate::iq::mex_ids::newsletter` for document IDs
//! - Standard IQ (xmlns="newsletter") for message operations

/// IQ namespace for newsletter operations (message history, reactions, live updates).
pub const NEWSLETTER_XMLNS: &str = "newsletter";
