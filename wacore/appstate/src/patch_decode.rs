//! Patch list parsing (snapshot + patches) - partial port of Go appstate/decode.go

use anyhow::{Result, anyhow};
use prost::Message;
use std::str::FromStr;
use wacore_binary::node::Node;
use waproto::whatsapp as wa;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WAPatchName {
    CriticalBlock,
    CriticalUnblockLow,
    RegularLow,
    RegularHigh,
    Regular,
    Unknown,
}

impl WAPatchName {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CriticalBlock => "critical_block",
            Self::CriticalUnblockLow => "critical_unblock_low",
            Self::RegularLow => "regular_low",
            Self::RegularHigh => "regular_high",
            Self::Regular => "regular",
            Self::Unknown => "unknown",
        }
    }
}

impl FromStr for WAPatchName {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "critical_block" => Self::CriticalBlock,
            "critical_unblock_low" => Self::CriticalUnblockLow,
            "regular_low" => Self::RegularLow,
            "regular_high" => Self::RegularHigh,
            "regular" => Self::Regular,
            _ => Self::Unknown,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PatchList {
    pub name: WAPatchName,
    pub has_more_patches: bool,
    pub patches: Vec<wa::SyncdPatch>,
    pub snapshot: Option<wa::SyncdSnapshot>, // filled only if already present inline (currently never)
    pub snapshot_ref: Option<wa::ExternalBlobReference>, // external reference to fetch
    /// Per-collection error from server (None = success).
    pub error: Option<CollectionSyncError>,
}

/// Per-collection error returned by the server inside a `<collection type="error">` node.
/// Matches WA Web's CollectionState enum (`GysEGRAXCvh.js:44755`).
#[derive(Debug, Clone)]
pub enum CollectionSyncError {
    /// 409: Version conflict — patches were applied concurrently.
    /// `has_more` indicates if there are more patches after resolving.
    Conflict { has_more: bool },
    /// 400 or 404: Unrecoverable server error.
    Fatal { code: u16, text: String },
    /// Any other error code: transient, can retry.
    Retry { code: u16, text: String },
}

impl std::fmt::Display for CollectionSyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict { has_more } => write!(f, "conflict (has_more={has_more})"),
            Self::Fatal { code, text } => write!(f, "fatal error {code}: {text}"),
            Self::Retry { code, text } => write!(f, "retryable error {code}: {text}"),
        }
    }
}

/// Parse an incoming app state collection node into a PatchList.
/// Node path: sync -> collection (attributes: name, has_more_patches)
pub fn parse_patch_list(node: &Node) -> Result<PatchList> {
    let collection = node
        .get_optional_child_by_tag(&["sync", "collection"]) // naive path descent
        .ok_or_else(|| anyhow!("missing sync/collection"))?;
    parse_single_collection(collection)
}

/// Parse all `<collection>` children from a `<sync>` response into PatchLists.
/// Used for batched multi-collection IQ responses.
/// Tolerates both `<iq><sync>...</sync></iq>` and bare `<sync>...</sync>` roots.
pub fn parse_patch_lists(node: &Node) -> Result<Vec<PatchList>> {
    let sync_node = if node.tag == "sync" {
        node
    } else {
        node.get_optional_child("sync")
            .ok_or_else(|| anyhow!("missing sync node in response"))?
    };

    let Some(children) = sync_node.children() else {
        return Ok(Vec::new());
    };

    children
        .iter()
        .filter(|c| c.tag == "collection")
        .map(parse_single_collection)
        .collect()
}

/// Parse a single `<collection>` node into a PatchList.
fn parse_single_collection(collection: &Node) -> Result<PatchList> {
    let mut ag = collection.attrs();
    let name_str = ag
        .optional_string("name")
        .ok_or_else(|| anyhow!("collection missing 'name' attribute"))?
        .to_string();
    let has_more = ag.optional_bool("has_more_patches");

    // Check for per-collection error (WA Web: `3JJWKHeu5-P.js:54222-54254`)
    let col_type = ag.optional_string("type");
    let error = parse_collection_error(collection, col_type.as_deref());

    ag.finish()?;

    // snapshot (optional)
    let mut snapshot_ref = None;
    if let Some(snapshot_node) = collection.get_optional_child("snapshot")
        && let Some(wacore_binary::node::NodeContent::Bytes(raw)) = &snapshot_node.content
        && let Ok(ext_ref) = wa::ExternalBlobReference::decode(raw.as_slice())
    {
        snapshot_ref = Some(ext_ref);
    }
    let snapshot = None; // external only currently

    // patches list
    let children_ref = collection
        .get_optional_child("patches")
        .and_then(|n| n.children());
    let mut patches: Vec<wa::SyncdPatch> =
        Vec::with_capacity(children_ref.as_ref().map_or(0, |c| c.len()));
    if let Some(children) = children_ref {
        for child in children {
            if child.tag == "patch"
                && let Some(wacore_binary::node::NodeContent::Bytes(raw)) = &child.content
            {
                match wa::SyncdPatch::decode(raw.as_slice()) {
                    Ok(p) => patches.push(p),
                    Err(e) => return Err(anyhow!("failed to unmarshal patch: {e}")),
                }
            }
        }
    }

    Ok(PatchList {
        name: WAPatchName::from_str(&name_str).unwrap_or(WAPatchName::Unknown),
        has_more_patches: has_more,
        patches,
        snapshot,
        snapshot_ref,
        error,
    })
}

/// Parse per-collection error from `<collection type="error"><error code="..." text="..."/>`.
/// Returns `None` for successful collections.
fn parse_collection_error(
    collection: &Node,
    col_type: Option<&str>,
) -> Option<CollectionSyncError> {
    if col_type? != "error" {
        return None;
    }

    // Parse error details from child node, or fall back to a default retryable
    // error if the <error> child is missing/malformed.
    let (code, text) = if let Some(error_node) = collection.get_optional_child("error") {
        let mut error_attrs = error_node.attrs();
        let code_str = error_attrs.optional_string("code");
        let text = error_attrs
            .optional_string("text")
            .as_deref()
            .unwrap_or("")
            .to_string();
        let code: u16 = code_str.as_deref().unwrap_or("0").parse().unwrap_or(0);
        (code, text)
    } else {
        (0u16, "missing <error> child".to_string())
    };

    Some(match code {
        409 => CollectionSyncError::Conflict {
            has_more: collection.attrs().optional_bool("has_more_patches"),
        },
        400 | 404 => CollectionSyncError::Fatal { code, text },
        _ => CollectionSyncError::Retry { code, text },
    })
}
