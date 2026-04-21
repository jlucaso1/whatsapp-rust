#![allow(clippy::type_complexity)]

pub use wacore::{
    iq::privacy as privacy_settings, proto_helpers, sticker_pack, store::traits, webp,
};
pub use wacore_binary::CompactString;
pub use wacore_binary::OwnedNodeRef;
pub use wacore_binary::builder::NodeBuilder;
pub use wacore_binary::{Jid, Server};
pub use waproto;

pub mod cache;
#[cfg(not(feature = "moka-cache"))]
pub mod portable_cache;

pub mod cache_config;
pub use cache_config::{CacheConfig, CacheEntryConfig, CacheStores};
pub mod cache_store;
pub(crate) mod pending_device_sync;
pub(crate) mod sender_key_device_cache;
pub use cache_store::CacheStore;
pub mod http;
pub mod types;

pub mod client;
pub(crate) mod flush_scope;
pub use client::Client;
#[cfg(feature = "debug-diagnostics")]
pub use client::MemoryDiagnostics;
pub use client::NodeFilter;
pub mod download;
pub mod handlers;
pub use handlers::chatstate::ChatStateEvent;
pub mod handshake;
pub mod jid_utils;
pub mod keepalive;
pub mod mediaconn;
pub mod message;
pub mod pair;
pub mod pair_code;
pub mod request;
#[cfg(feature = "tokio-runtime")]
pub mod runtime_impl;
#[cfg(feature = "tokio-runtime")]
pub use runtime_impl::TokioRuntime;
pub use wacore::runtime::Runtime;
pub mod send;
pub use send::{PinDuration, RevokeType, SendOptions, SendResult};
pub mod session;
pub mod socket;
pub mod store;
pub mod transport;
pub mod upload;
pub use upload::UploadOptions;

pub mod pdo;
pub mod prekeys;
pub mod receipt;
pub mod retry;
pub mod unified_session;

pub mod appstate_sync;
pub mod calls;
pub mod history_sync;
pub mod usync;

pub mod features;
pub use features::{
    BatchGroupResult, Blocking, BlocklistEntry, ChatActions, ChatStateType, Chatstate, Community,
    CommunitySubgroup, Contacts, CreateCommunityOptions, CreateCommunityResult, CreateGroupResult,
    GroupCreateOptions, GroupDescription, GroupJoinError, GroupMetadata, GroupParticipant,
    GroupParticipantOptions, GroupProfilePicture, GroupSubject, GroupType, Groups, GrowthLockInfo,
    InviteInfoError, IsOnWhatsAppResult, JoinGroupResult, LinkSubgroupsResult, MediaRetryResult,
    MediaReupload, MediaReuploadRequest, MemberAddMode, MemberLinkMode, MemberShareHistoryMode,
    MembershipApprovalMode, MembershipRequest, Mex, MexError, MexErrorExtensions, MexRequest,
    MexResponse, Newsletter, NewsletterMessage, NewsletterMessageType, NewsletterMetadata,
    NewsletterReactionCount, NewsletterRole, NewsletterState, NewsletterVerification,
    ParticipantChangeResponse, ParticipantType, PictureType, Presence, PresenceError,
    PresenceStatus, Profile, ProfilePicture, SetProfilePictureResponse, Signal, Status,
    StatusPrivacySetting, StatusSendOptions, SyncActionMessageRange, TcToken,
    UnlinkSubgroupsResult, UserInfo, group_type, message_key, message_range,
};

pub mod bot;
pub mod lid_pn_cache;
pub mod spam_report;
pub mod sync_task;
pub mod version;

pub use spam_report::{SpamFlow, SpamReportRequest, SpamReportResult};

#[cfg(test)]
pub mod test_utils;
