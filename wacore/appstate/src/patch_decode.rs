//! Patch list parsing (snapshot + patches) - partial port of Go appstate/decode.go

use anyhow::{Result, anyhow};
use prost::Message;
use std::str::FromStr;
use wacore_binary::node::Node;
use waproto::whatsapp as wa;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

/// Parse an incoming app state collection node into a PatchList.
/// Node path: sync -> collection (attributes: name, has_more_patches)
pub fn parse_patch_list(node: &Node) -> Result<PatchList> {
    let collection = node
        .get_optional_child_by_tag(&["sync", "collection"]) // naive path descent
        .ok_or_else(|| anyhow!("missing sync/collection"))?;
    let mut ag = collection.attrs();
    let name_str = ag
        .optional_string("name")
        .ok_or_else(|| anyhow!("collection missing 'name' attribute"))?
        .to_string();
    let has_more = ag.optional_bool("has_more_patches");
    ag.finish()?; // propagate attr parse errors

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
    let mut patches: Vec<wa::SyncdPatch> = Vec::new();
    if let Some(patches_node) = collection.get_optional_child("patches")
        && let Some(children) = patches_node.children()
    {
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
    })
}
