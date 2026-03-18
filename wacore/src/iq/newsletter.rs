//! Newsletter (Channel) IQ specifications.
//!
//! Newsletters use two protocol layers:
//! - Mex (GraphQL) for metadata/management operations
//! - Standard IQ (xmlns="newsletter") for message operations

/// Mex document IDs for newsletter GraphQL operations.
pub mod mex_docs {
    pub const LIST_SUBSCRIBED: &str = "33101596156151910";
    pub const FETCH_METADATA: &str = "25383075034668475";
    pub const FETCH_DEHYDRATED: &str = "30328461880085868";
    pub const CREATE: &str = "25149874324715067";
    pub const UPDATE: &str = "24250201037901610";
    pub const JOIN: &str = "24404358912487870";
    pub const FETCH_ADMIN_COUNT: &str = "29186079397702825";
    pub const FETCH_ADMIN_CAPABILITIES: &str = "9801384413216421";
    pub const FETCH_PENDING_INVITES: &str = "9783111038412085";
    pub const FETCH_SUBSCRIBERS: &str = "9537574256318798";
    pub const FETCH_REACTION_SENDERS: &str = "29575462448733991";
    pub const LEAVE: &str = "9767147403369991";
}

/// IQ namespace for newsletter operations (message history, reactions, live updates).
pub const NEWSLETTER_XMLNS: &str = "newsletter";
