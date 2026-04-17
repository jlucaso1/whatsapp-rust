//! Parser for inbound `<call>` stanzas. Returns `Ok(None)` on unknown action
//! children so future server additions don't break the handler.

use anyhow::{Result, anyhow};
use wacore_binary::NodeRef;

use crate::time::from_secs;
use crate::types::call::{CallAction, CallAudioCodec, IncomingCall};

const KNOWN_ACTIONS: &[&str] = &["offer", "pre-accept", "accept", "reject", "terminate"];

pub fn parse_call_stanza(node: &NodeRef<'_>) -> Result<Option<IncomingCall>> {
    if node.tag != "call" {
        return Err(anyhow!("expected <call>, got <{}>", node.tag));
    }

    let mut attrs = node.attrs();
    let from = attrs
        .optional_jid("from")
        .ok_or_else(|| anyhow!("<call> missing 'from' attribute"))?;
    let stanza_id = attrs
        .required_string("id")
        .map_err(|e| anyhow!("<call> missing 'id': {e}"))?
        .into_owned();
    let notify = attrs
        .optional_string("notify")
        .and_then(|s| (!s.is_empty()).then(|| s.into_owned()));
    let platform = attrs.optional_string("platform").map(|s| s.into_owned());
    let version = attrs.optional_string("version").map(|s| s.into_owned());
    let ts = attrs
        .optional_unix_time("t")
        .ok_or_else(|| anyhow!("<call> missing or invalid 't' attribute"))?;
    let timestamp = from_secs(ts).ok_or_else(|| anyhow!("<call> 't'={ts} out of range"))?;
    let offline = attrs.optional_string("e").is_some_and(|s| s == "1");

    attrs.finish().map_err(|e| anyhow!("<call> attrs: {e}"))?;

    let Some(child) = node
        .children()
        .and_then(|cs| cs.iter().find(|c| KNOWN_ACTIONS.contains(&c.tag.as_ref())))
    else {
        return Ok(None);
    };

    let action = parse_action(child)?;

    Ok(Some(IncomingCall {
        from,
        stanza_id,
        notify,
        platform,
        version,
        timestamp,
        offline,
        action,
    }))
}

fn parse_action(node: &NodeRef<'_>) -> Result<CallAction> {
    let mut attrs = node.attrs();
    let call_id = attrs
        .required_string("call-id")
        .map_err(|e| anyhow!("<{}> missing 'call-id': {e}", node.tag))?
        .into_owned();
    let call_creator = attrs
        .optional_jid("call-creator")
        .ok_or_else(|| anyhow!("<{}> missing 'call-creator'", node.tag))?;

    Ok(match node.tag.as_ref() {
        "offer" => {
            let caller_pn = attrs.optional_jid("caller_pn");
            let caller_country_code = attrs
                .optional_string("caller_country_code")
                .map(|s| s.into_owned());
            let device_class = attrs
                .optional_string("device_class")
                .map(|s| s.into_owned());
            let joinable = attrs
                .optional_string("joinable")
                .map(|s| s == "1")
                .unwrap_or(false);

            attrs.finish().map_err(|e| anyhow!("<offer> attrs: {e}"))?;

            let children = node.children().unwrap_or_default();
            let is_video = children.iter().any(|c| c.tag == "video");
            let audio: Vec<CallAudioCodec> = children
                .iter()
                .filter(|c| c.tag == "audio")
                .filter_map(|c| {
                    let mut a = c.attrs();
                    let enc = a.optional_string("enc")?.into_owned();
                    let rate = a
                        .optional_u64("rate")
                        .and_then(|r| u32::try_from(r).ok())
                        .unwrap_or(0);
                    Some(CallAudioCodec { enc, rate })
                })
                .collect();

            CallAction::Offer {
                call_id,
                call_creator,
                caller_pn,
                caller_country_code,
                device_class,
                joinable,
                is_video,
                audio,
            }
        }
        "pre-accept" => CallAction::PreAccept {
            call_id,
            call_creator,
        },
        "accept" => CallAction::Accept {
            call_id,
            call_creator,
        },
        "reject" => CallAction::Reject {
            call_id,
            call_creator,
        },
        "terminate" => {
            let duration = attrs
                .optional_u64("duration")
                .and_then(|v| u32::try_from(v).ok());
            let audio_duration = attrs
                .optional_u64("audio_duration")
                .and_then(|v| u32::try_from(v).ok());
            CallAction::Terminate {
                call_id,
                call_creator,
                duration,
                audio_duration,
            }
        }
        other => return Err(anyhow!("unreachable: unknown action <{other}>")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wacore_binary::builder::NodeBuilder;
    use wacore_binary::{Jid, Server};

    fn caller_lid() -> Jid {
        Jid::new("271240153559280", Server::Lid)
    }

    fn caller_pn_jid() -> Jid {
        Jid::new("559984726682", Server::Pn)
    }

    fn base_call_builder() -> NodeBuilder {
        NodeBuilder::new("call")
            .attr("from", caller_lid())
            .attr("id", "749D3EE94DC6B008974C36460DA2D9BC")
            .attr("version", "2.25.37.76")
            .attr("platform", "android")
            .attr("notify", "Elis")
            .attr("t", "1766847151")
            .attr("e", "0")
    }

    fn offer_builder_base() -> NodeBuilder {
        NodeBuilder::new("offer")
            .attr("call-creator", caller_lid())
            .attr("call-id", "AC589ABE46B3770DC5B7A143D007DC3E")
    }

    fn as_ref<'a>(n: &'a wacore_binary::Node) -> NodeRef<'a> {
        n.as_node_ref()
    }

    #[test]
    fn offer_audio_only() {
        let node = base_call_builder()
            .children([offer_builder_base()
                .attr("caller_pn", caller_pn_jid())
                .attr("device_class", "2016")
                .attr("joinable", "1")
                .attr("caller_country_code", "BR")
                .children([
                    NodeBuilder::new("audio")
                        .attr("enc", "opus")
                        .attr("rate", "16000")
                        .build(),
                    NodeBuilder::new("audio")
                        .attr("enc", "opus")
                        .attr("rate", "8000")
                        .build(),
                ])
                .build()])
            .build();

        let call = parse_call_stanza(&as_ref(&node)).unwrap().unwrap();
        assert_eq!(call.stanza_id, "749D3EE94DC6B008974C36460DA2D9BC");
        assert_eq!(call.from, caller_lid());
        assert_eq!(call.timestamp.timestamp(), 1766847151);
        assert!(!call.offline);
        assert_eq!(call.notify.as_deref(), Some("Elis"));
        assert_eq!(call.platform.as_deref(), Some("android"));

        match call.action {
            CallAction::Offer {
                call_id,
                call_creator,
                caller_pn,
                caller_country_code,
                device_class,
                joinable,
                is_video,
                audio,
            } => {
                assert_eq!(call_id, "AC589ABE46B3770DC5B7A143D007DC3E");
                assert_eq!(call_creator, caller_lid());
                assert_eq!(caller_pn, Some(caller_pn_jid()));
                assert_eq!(caller_country_code.as_deref(), Some("BR"));
                assert_eq!(device_class.as_deref(), Some("2016"));
                assert!(joinable);
                assert!(!is_video);
                assert_eq!(audio.len(), 2);
                assert_eq!(audio[0].enc, "opus");
                assert_eq!(audio[0].rate, 16000);
                assert_eq!(audio[1].rate, 8000);
            }
            other => panic!("expected Offer, got {other:?}"),
        }
    }

    #[test]
    fn offer_video() {
        let node = base_call_builder()
            .children([offer_builder_base()
                .children([
                    NodeBuilder::new("audio")
                        .attr("enc", "opus")
                        .attr("rate", "16000")
                        .build(),
                    NodeBuilder::new("video").build(),
                ])
                .build()])
            .build();

        let call = parse_call_stanza(&as_ref(&node)).unwrap().unwrap();
        match call.action {
            CallAction::Offer {
                is_video, audio, ..
            } => {
                assert!(is_video);
                assert_eq!(audio.len(), 1);
            }
            other => panic!("expected Offer, got {other:?}"),
        }
    }

    #[test]
    fn offer_minimum_attrs() {
        let node = NodeBuilder::new("call")
            .attr("from", caller_lid())
            .attr("id", "STANZA1")
            .attr("t", "1766847151")
            .children([offer_builder_base().build()])
            .build();

        let call = parse_call_stanza(&as_ref(&node)).unwrap().unwrap();
        assert_eq!(call.notify, None);
        assert_eq!(call.platform, None);
        assert_eq!(call.version, None);
        match call.action {
            CallAction::Offer {
                caller_pn,
                caller_country_code,
                device_class,
                joinable,
                is_video,
                audio,
                ..
            } => {
                assert_eq!(caller_pn, None);
                assert_eq!(caller_country_code, None);
                assert_eq!(device_class, None);
                assert!(!joinable);
                assert!(!is_video);
                assert!(audio.is_empty());
            }
            other => panic!("expected Offer, got {other:?}"),
        }
    }

    #[test]
    fn pre_accept_accept_reject_variants() {
        for (tag, expected_variant) in [
            ("pre-accept", "pre_accept"),
            ("accept", "accept"),
            ("reject", "reject"),
        ] {
            let node = base_call_builder()
                .children([NodeBuilder::new(tag)
                    .attr("call-creator", caller_lid())
                    .attr("call-id", "CID")
                    .build()])
                .build();

            let call = parse_call_stanza(&as_ref(&node)).unwrap().unwrap();
            assert_eq!(call.action.call_id(), "CID");
            let name = match call.action {
                CallAction::PreAccept { .. } => "pre_accept",
                CallAction::Accept { .. } => "accept",
                CallAction::Reject { .. } => "reject",
                _ => "other",
            };
            assert_eq!(name, expected_variant);
        }
    }

    #[test]
    fn terminate_with_duration() {
        let node = base_call_builder()
            .children([NodeBuilder::new("terminate")
                .attr("call-creator", caller_lid())
                .attr("call-id", "CID")
                .attr("duration", "3670")
                .attr("audio_duration", "3670")
                .build()])
            .build();

        let call = parse_call_stanza(&as_ref(&node)).unwrap().unwrap();
        match call.action {
            CallAction::Terminate {
                duration,
                audio_duration,
                ..
            } => {
                assert_eq!(duration, Some(3670));
                assert_eq!(audio_duration, Some(3670));
            }
            other => panic!("expected Terminate, got {other:?}"),
        }
    }

    #[test]
    fn unknown_action_returns_none() {
        let node = base_call_builder()
            .children([NodeBuilder::new("surprise").build()])
            .build();
        assert!(parse_call_stanza(&as_ref(&node)).unwrap().is_none());
    }

    #[test]
    fn malformed_missing_t_errors() {
        let node = NodeBuilder::new("call")
            .attr("from", caller_lid())
            .attr("id", "STANZA1")
            .children([offer_builder_base().build()])
            .build();

        assert!(parse_call_stanza(&as_ref(&node)).is_err());
    }

    #[test]
    fn offline_delivery_flag() {
        let offline_node = NodeBuilder::new("call")
            .attr("from", caller_lid())
            .attr("id", "S")
            .attr("t", "1766847151")
            .attr("e", "1")
            .children([offer_builder_base().build()])
            .build();
        assert!(
            parse_call_stanza(&as_ref(&offline_node))
                .unwrap()
                .unwrap()
                .offline
        );

        let online_node = NodeBuilder::new("call")
            .attr("from", caller_lid())
            .attr("id", "S")
            .attr("t", "1766847151")
            .children([offer_builder_base().build()])
            .build();
        assert!(
            !parse_call_stanza(&as_ref(&online_node))
                .unwrap()
                .unwrap()
                .offline
        );
    }
}
