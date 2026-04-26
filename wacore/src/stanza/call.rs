//! Parser for inbound `<call>` stanzas. Returns `Ok(None)` on unknown action
//! children so future server additions don't break the handler.

use anyhow::{Result, anyhow};
use log::debug;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::{Jid, Node, NodeRef};

use crate::time::from_secs;
use crate::types::call::{CallAction, CallAudioCodec, IncomingCall};

const KNOWN_ACTIONS: &[&str] = &[
    "offer",
    "offer_notice",
    "preaccept",
    "accept",
    "reject",
    "terminate",
];

pub fn parse_call_stanza(node: &NodeRef<'_>) -> Result<Option<IncomingCall>> {
    if node.tag != "call" {
        return Err(anyhow!("expected <call>, got <{}>", node.tag));
    }

    // Find a known action child first so unknown/future actions short-circuit
    // before attr validation (forward-compat, even if stanza attrs also shift).
    let Some(child) = node
        .children()
        .and_then(|cs| cs.iter().find(|c| KNOWN_ACTIONS.contains(&c.tag.as_ref())))
    else {
        return Ok(None);
    };

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

fn parse_audio_codec(node: &NodeRef<'_>) -> Result<CallAudioCodec> {
    let mut a = node.attrs();
    let enc = a
        .required_string("enc")
        .map_err(|e| anyhow!("<audio> missing 'enc': {e}"))?
        .into_owned();
    let rate_raw = a
        .optional_u64("rate")
        .ok_or_else(|| anyhow!("<audio enc={enc}> missing or invalid 'rate'"))?;
    let rate = u32::try_from(rate_raw)
        .map_err(|_| anyhow!("<audio enc={enc}> 'rate'={rate_raw} overflows u32"))?;
    a.finish().map_err(|e| anyhow!("<audio> attrs: {e}"))?;
    Ok(CallAudioCodec { enc, rate })
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
            // Baileys (Socket/messages-recv.ts:1552-1553): grupo pode vir como
            // `type="group"` ou `group-jid="...@g.us"`. Expomos os 2 — alguns
            // layouts trazem só `type` sem `group-jid`, então o consumidor
            // precisa dos 2 sinais pra detectar.
            let is_group_type = attrs.optional_string("type").is_some_and(|s| s == "group");
            let group_jid = attrs.optional_jid("group-jid");

            attrs.finish().map_err(|e| anyhow!("<offer> attrs: {e}"))?;

            let children = node.children().unwrap_or_default();
            let is_video = children.iter().any(|c| c.tag == "video");
            let audio = children
                .iter()
                .filter(|c| c.tag == "audio")
                .map(parse_audio_codec)
                .collect::<Result<Vec<_>>>()?;

            CallAction::Offer {
                call_id,
                call_creator,
                caller_pn,
                caller_country_code,
                device_class,
                joinable,
                is_video,
                audio,
                group_jid,
                is_group_type,
            }
        }
        "offer_notice" => {
            let media = attrs.optional_string("media").map(|s| s.into_owned());
            let caller_pn = attrs.optional_jid("caller_pn");
            // `type` and `reason` aren't used downstream but logging them at
            // debug level keeps observability so future protocol drift
            // doesn't degrade silently.
            let unhandled_type = attrs.optional_string("type");
            let unhandled_reason = attrs.optional_string("reason");
            if unhandled_type.is_some() || unhandled_reason.is_some() {
                debug!(
                    "<offer_notice> unhandled attrs: type={:?} reason={:?} call_id={} call_creator={}",
                    unhandled_type.as_deref(),
                    unhandled_reason.as_deref(),
                    call_id,
                    call_creator
                );
            }
            CallAction::OfferNotice {
                call_id,
                call_creator,
                media,
                caller_pn,
            }
        }
        "preaccept" => CallAction::PreAccept {
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
            attrs
                .finish()
                .map_err(|e| anyhow!("<terminate> attrs: {e}"))?;
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

/// Build `<receipt to=caller id=stanza_id [from=own_ad]><offer call-id call-creator/></receipt>`
/// for acknowledging an incoming `<offer>`. Pure so it can be unit-tested
/// without a live socket.
pub fn build_offer_ack_receipt(call: &IncomingCall, own_ad: Option<&Jid>) -> Option<Node> {
    let CallAction::Offer {
        call_id,
        call_creator,
        ..
    } = &call.action
    else {
        return None;
    };

    let mut receipt = NodeBuilder::new("receipt")
        .attr("to", &call.from)
        .attr("id", call.stanza_id.as_str());
    if let Some(jid) = own_ad {
        receipt = receipt.attr("from", jid);
    }

    let offer = NodeBuilder::new("offer")
        .attr("call-id", call_id.as_str())
        .attr("call-creator", call_creator)
        .build();

    Some(receipt.children([offer]).build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wacore_binary::builder::NodeBuilder;
    use wacore_binary::{Jid, Server};

    fn fake_caller_lid() -> Jid {
        Jid::new("111111111111111", Server::Lid)
    }

    fn fake_caller_pn() -> Jid {
        Jid::new("15555550100", Server::Pn)
    }

    fn base_call_builder() -> NodeBuilder {
        NodeBuilder::new("call")
            .attr("from", fake_caller_lid())
            .attr("id", "STANZA-ID-0001")
            .attr("version", "2.25.37.76")
            .attr("platform", "android")
            .attr("notify", "Test Caller")
            .attr("t", "1766847151")
            .attr("e", "0")
    }

    fn offer_builder_base() -> NodeBuilder {
        NodeBuilder::new("offer")
            .attr("call-creator", fake_caller_lid())
            .attr("call-id", "CALL-ID-0001")
    }

    fn as_ref<'a>(n: &'a wacore_binary::Node) -> NodeRef<'a> {
        n.as_node_ref()
    }

    #[test]
    fn offer_audio_only() {
        let node = base_call_builder()
            .children([offer_builder_base()
                .attr("caller_pn", fake_caller_pn())
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
        assert_eq!(call.stanza_id, "STANZA-ID-0001");
        assert_eq!(call.from, fake_caller_lid());
        assert_eq!(call.timestamp.timestamp(), 1766847151);
        assert!(!call.offline);
        assert_eq!(call.notify.as_deref(), Some("Test Caller"));
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
                group_jid,
                is_group_type,
            } => {
                assert_eq!(call_id, "CALL-ID-0001");
                assert_eq!(call_creator, fake_caller_lid());
                assert_eq!(caller_pn, Some(fake_caller_pn()));
                assert_eq!(caller_country_code.as_deref(), Some("BR"));
                assert_eq!(device_class.as_deref(), Some("2016"));
                assert!(joinable);
                assert!(!is_video);
                assert_eq!(audio.len(), 2);
                assert_eq!(audio[0].enc, "opus");
                assert_eq!(audio[0].rate, 16000);
                assert_eq!(audio[1].rate, 8000);
                assert_eq!(group_jid, None);
                assert!(!is_group_type);
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
            .attr("from", fake_caller_lid())
            .attr("id", "STANZA-ID-0001")
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

    /// `<offer>` carrying explicit group context — `type="group"` and
    /// `group-jid="…@g.us"` per Baileys (`Socket/messages-recv.ts:1552`).
    /// Distinct from `<offer_notice>` (the more common signaling shape).
    #[test]
    fn offer_with_group_jid_and_type() {
        let group_jid = Jid::new("123456789", Server::Group);
        let node = base_call_builder()
            .children([offer_builder_base()
                .attr("type", "group")
                .attr("group-jid", group_jid.clone())
                .children([NodeBuilder::new("audio")
                    .attr("enc", "opus")
                    .attr("rate", "16000")
                    .build()])
                .build()])
            .build();

        let call = parse_call_stanza(&as_ref(&node)).unwrap().unwrap();
        match call.action {
            CallAction::Offer {
                group_jid: parsed_group,
                is_group_type,
                is_video,
                audio,
                ..
            } => {
                assert_eq!(parsed_group, Some(group_jid));
                assert!(is_group_type);
                assert!(!is_video);
                assert_eq!(audio.len(), 1);
            }
            other => panic!("expected Offer, got {other:?}"),
        }
    }

    /// `<offer>` with only `type="group"` and no `group-jid` — Baileys treats
    /// this as a group call too. Tests that `is_group_type` carries the signal
    /// even when `group-jid` is absent.
    #[test]
    fn offer_with_only_type_group() {
        let node = base_call_builder()
            .children([offer_builder_base().attr("type", "group").build()])
            .build();

        let call = parse_call_stanza(&as_ref(&node)).unwrap().unwrap();
        match call.action {
            CallAction::Offer {
                group_jid,
                is_group_type,
                ..
            } => {
                assert_eq!(group_jid, None);
                assert!(is_group_type);
            }
            other => panic!("expected Offer, got {other:?}"),
        }
    }

    /// Group call signaling: WA Web entrega `<offer_notice type="group">` aos
    /// membros do grupo (não `<offer>`). Captured stanza shape from production:
    /// `<call from=caller@lid id=... t=...><offer_notice call-creator=caller@lid
    /// call-id=... media=audio type=group reason=427 caller_pn=...></offer_notice></call>`.
    #[test]
    fn offer_notice_group_call() {
        let node = NodeBuilder::new("call")
            .attr("from", fake_caller_lid())
            .attr("id", "STANZA-ID-GROUP")
            .attr("t", "1766847151")
            .children([NodeBuilder::new("offer_notice")
                .attr("call-creator", fake_caller_lid())
                .attr("call-id", "GROUP-CALL-ID")
                .attr("media", "audio")
                .attr("type", "group")
                .attr("reason", "427")
                .attr("caller_pn", fake_caller_pn())
                .build()])
            .build();

        let call = parse_call_stanza(&as_ref(&node)).unwrap().unwrap();
        match call.action {
            CallAction::OfferNotice {
                call_id,
                call_creator,
                media,
                caller_pn,
            } => {
                assert_eq!(call_id, "GROUP-CALL-ID");
                assert_eq!(call_creator, fake_caller_lid());
                assert_eq!(media.as_deref(), Some("audio"));
                assert_eq!(caller_pn, Some(fake_caller_pn()));
            }
            other => panic!("expected OfferNotice, got {other:?}"),
        }
    }

    #[test]
    fn preaccept_accept_reject_variants() {
        for (tag, expected_variant) in [
            ("preaccept", "pre_accept"),
            ("accept", "accept"),
            ("reject", "reject"),
        ] {
            let node = base_call_builder()
                .children([NodeBuilder::new(tag)
                    .attr("call-creator", fake_caller_lid())
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
                .attr("call-creator", fake_caller_lid())
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
    fn unknown_action_short_circuits_before_attr_validation() {
        // No `t` attr, but unknown action means we never validate it.
        let node = NodeBuilder::new("call")
            .attr("from", fake_caller_lid())
            .attr("id", "S")
            .children([NodeBuilder::new("surprise").build()])
            .build();
        assert!(parse_call_stanza(&as_ref(&node)).unwrap().is_none());
    }

    #[test]
    fn malformed_audio_missing_enc_errors() {
        let node = base_call_builder()
            .children([offer_builder_base()
                .children([NodeBuilder::new("audio").attr("rate", "16000").build()])
                .build()])
            .build();

        assert!(parse_call_stanza(&as_ref(&node)).is_err());
    }

    #[test]
    fn malformed_audio_missing_rate_errors() {
        let node = base_call_builder()
            .children([offer_builder_base()
                .children([NodeBuilder::new("audio").attr("enc", "opus").build()])
                .build()])
            .build();

        assert!(parse_call_stanza(&as_ref(&node)).is_err());
    }

    #[test]
    fn malformed_audio_rate_overflow_errors() {
        let node = base_call_builder()
            .children([offer_builder_base()
                .children([NodeBuilder::new("audio")
                    .attr("enc", "opus")
                    .attr("rate", "4294967296") // u32::MAX + 1
                    .build()])
                .build()])
            .build();

        assert!(parse_call_stanza(&as_ref(&node)).is_err());
    }

    #[test]
    fn malformed_missing_t_errors() {
        let node = NodeBuilder::new("call")
            .attr("from", fake_caller_lid())
            .attr("id", "STANZA-ID-0001")
            .children([offer_builder_base().build()])
            .build();

        assert!(parse_call_stanza(&as_ref(&node)).is_err());
    }

    #[test]
    fn offline_delivery_flag() {
        let offline_node = NodeBuilder::new("call")
            .attr("from", fake_caller_lid())
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
            .attr("from", fake_caller_lid())
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

    #[test]
    fn build_offer_ack_receipt_matches_wa_web_shape() {
        let node = base_call_builder()
            .children([offer_builder_base().build()])
            .build();
        let call = parse_call_stanza(&as_ref(&node)).unwrap().unwrap();
        let own = Jid::new("222222222222222", Server::Lid).with_device(42);

        let receipt = build_offer_ack_receipt(&call, Some(&own)).unwrap();
        assert_eq!(receipt.tag.as_ref(), "receipt");

        let mut a = receipt.attrs();
        assert_eq!(
            a.required_string("to").unwrap(),
            fake_caller_lid().to_string()
        );
        assert_eq!(a.required_string("id").unwrap(), "STANZA-ID-0001");
        assert_eq!(a.required_string("from").unwrap(), own.to_string());

        let offer = receipt.get_optional_child("offer").unwrap();
        let mut oa = offer.attrs();
        assert_eq!(oa.required_string("call-id").unwrap(), "CALL-ID-0001");
        assert_eq!(
            oa.required_string("call-creator").unwrap(),
            fake_caller_lid().to_string()
        );
    }

    #[test]
    fn build_offer_ack_receipt_returns_none_for_non_offer() {
        let node = base_call_builder()
            .children([NodeBuilder::new("reject")
                .attr("call-creator", fake_caller_lid())
                .attr("call-id", "X")
                .build()])
            .build();
        let call = parse_call_stanza(&as_ref(&node)).unwrap().unwrap();
        assert!(build_offer_ack_receipt(&call, None).is_none());
    }

    #[test]
    fn build_offer_ack_receipt_omits_from_when_own_ad_missing() {
        let node = base_call_builder()
            .children([offer_builder_base().build()])
            .build();
        let call = parse_call_stanza(&as_ref(&node)).unwrap().unwrap();
        let receipt = build_offer_ack_receipt(&call, None).unwrap();
        let mut a = receipt.attrs();
        assert!(a.optional_string("from").is_none());
    }
}
