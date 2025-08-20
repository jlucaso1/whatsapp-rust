use crate::store::commands::DeviceCommand;
use crate::store::persistence_manager::PersistenceManager;
use anyhow::{Result, anyhow};
use log::{info, warn};
use std::io::Read;
use std::sync::Arc;

const SW_URL: &str = "https://web.whatsapp.com/sw.js";
const REVISION_KEY: &str = "client_revision";
const ASSETS_KEY: &str = "assets-manifest-";

pub fn fetch_latest_app_version() -> Result<(u32, u32, u32)> {
    let resp = ureq::get(SW_URL)
        .call()
        .map_err(|e| anyhow!("HTTP request to {} failed: {}", SW_URL, e))?;

    let mut body = resp.into_body();
    let mut reader = body.as_reader();

    let mut body_str = String::new();
    reader
        .read_to_string(&mut body_str)
        .map_err(|e| anyhow!("Failed to read response body: {}", e))?;

    parse_sw_js(&body_str)
        .ok_or_else(|| anyhow!("Could not find 'client_revision' version in sw.js response"))
}

fn parse_sw_js(s: &str) -> Option<(u32, u32, u32)> {
    if let Some(start_index) = s.find(REVISION_KEY) {
        let suffix = &s[start_index + REVISION_KEY.len()..];

        if let Some(first_digit_index) = suffix.find(|c: char| c.is_ascii_digit()) {
            let number_slice = &suffix[first_digit_index..];

            let end_of_number_index = number_slice
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(number_slice.len());

            let version_str = &number_slice[..end_of_number_index];

            if let Ok(revision) = version_str.parse::<u32>() {
                return Some((2, 3000, revision));
            }
        }
    }

    if let Some(start_index) = s.find(ASSETS_KEY) {
        let suffix = &s[start_index + ASSETS_KEY.len()..];
        if let Some(end_index) = suffix.find(|c: char| !c.is_ascii_digit()) {
            let version_str = &suffix[..end_index];
            if !s.contains(&format!("wa{}.canary", version_str)) {
                return Some((2, 3000, 0));
            }
        }
    }

    None
}

pub async fn resolve_and_update_version(
    persistence_manager: &Arc<PersistenceManager>,
    override_version: Option<(u32, u32, u32)>,
) {
    if let Some((p, s, t)) = override_version {
        info!("Using user-provided override version: {}.{}.{}", p, s, t);
        persistence_manager
            .process_command(DeviceCommand::SetAppVersion((p, s, t)))
            .await;
        return;
    }

    let device = persistence_manager.get_device_snapshot().await;
    let last_fetched_ms = device.app_version_last_fetched_ms;

    let needs_fetch = if last_fetched_ms == 0 {
        true
    } else {
        match chrono::DateTime::from_timestamp_millis(last_fetched_ms) {
            Some(last_fetched_dt) => {
                chrono::Utc::now().signed_duration_since(last_fetched_dt)
                    > chrono::Duration::hours(24)
            }
            None => true,
        }
    };

    if needs_fetch {
        info!("WhatsApp version is stale or missing, fetching latest...");
        match tokio::task::spawn_blocking(fetch_latest_app_version).await {
            Ok(Ok((p, s, t))) => {
                info!("Fetched latest version: {}.{}.{}", p, s, t);
                persistence_manager
                    .process_command(DeviceCommand::SetAppVersion((p, s, t)))
                    .await;
            }
            Ok(Err(e)) => {
                warn!(
                    "Failed to fetch latest version, using cached/default: {}",
                    e
                );
            }
            Err(e) => {
                warn!("Version fetch task panicked: {}", e);
            }
        }
    } else {
        info!(
            "Using cached version: {}.{}.{}",
            device.app_version_primary, device.app_version_secondary, device.app_version_tertiary
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sw_js_client_revision_quoted() {
        let s = r#"var x = {"client_revision": "123456"};"#;
        assert_eq!(parse_sw_js(s), Some((2, 3000, 123456)));
    }

    #[test]
    fn test_parse_sw_js_client_revision_unquoted() {
        let s = r#"client_revision:12345;"#;
        assert_eq!(parse_sw_js(s), Some((2, 3000, 12345)));
    }

    #[test]
    fn test_parse_sw_js_assets_fallback() {
        let s = "... assets-manifest-98765 ...";
        assert_eq!(parse_sw_js(s), Some((2, 3000, 0)));
    }

    #[test]
    fn test_parse_sw_js_realistic_sw_js() {
        let s = r#"__DEV__=0;/*FB_PKG_DELIM*/
self.__swData=JSON.parse(/*BTDS*/"{\"dynamic_data\":{\"dynamic_modules\":{\"cr:375\":{\"__rc\":[\"WAWebFtsLightClient\",null]},\"cr:1126\":{\"__rc\":[\"TimeSliceSham\",null]},\"cr:4122\":{\"__rc\":[null,null]},\"cr:4324\":{\"__rc\":[null,null]},\"cr:4533\":{\"__rc\":[null,null]},\"cr:4722\":{\"__rc\":[null,null]},\"cr:4941\":{\"__rc\":[null,null]},\"cr:5151\":{\"__rc\":[null,null]},\"cr:5292\":{\"__rc\":[null,null]},\"cr:5411\":{\"__rc\":[null,null]},\"cr:5664\":{\"__rc\":[null,null]},\"cr:6640\":{\"__rc\":[null,null]},\"cr:8978\":{\"__rc\":[null,null]},\"cr:9565\":{\"__rc\":[null,null]},\"cr:10197\":{\"__rc\":[null,null]},\"cr:10198\":{\"__rc\":[null,null]},\"cr:17160\":{\"__rc\":[null,null]},\"cr:17219\":{\"__rc\":[null,null]},\"cr:21223\":{\"__rc\":[null,null]},\"IntlCurrentLocale\":{\"code\":\"en_US\"},\"WAWebSwResources\":{\"wa_default_notification_icon\":\"https:\\\/\\\/static.whatsapp.net\\\/rsrc.php\\\/v4\\\/yX\\\/r\\\/JYPizEwERE4.png\"},\"SiteData\":{\"server_revision\":1026131876,\"client_revision\":1026131876,\"push_phase\":\"C3\",\"pkg_cohort\":\"BP:DEFAULT\",\"haste_session\":\"20320.BP:DEFAULT.2.0...0\",\"pr\":1,\"manifest_base_uri\":\"https:\\\/\\\/static.whatsapp.net\",\"manifest_origin\":null,\"manifest_version_prefix\":null,\"be_one_ahead\":false,\"is_rtl\":false,\"is_experimental_tier\":false,\"is_jit_warmed_up\":true,\"hsi\":\"7540800780599698108\",\"semr_host_bucket\":\"3\",\"bl_hash_version\":2,\"comet_env\":0,\"wbloks_env\":false,\"ef_page\":null,\"compose_bootloads\":false,\"spin\":4,\"__spin_r\":1026131876,\"__spin_b\":\"trunk\",\"__spin_t\":1755729499,\"vip\":\"2a03:2880:f205:c5:face:b00c:0:167\"}},\"hsdp\":{\"bxData\":{\"32186\":{\"uri\":\"https:\\\/\\\/static.whatsapp.net\\\/rsrc.php\\\/v4\\\/yR\\\/r\\\/aCneqBxOSs-.png\"},\"32187\":{\"uri\":\"https:\\\/\\\/static.whatsapp.net\\\/rsrc.php\\\/v4\\\/yT\\\/r\\\/s0hoT-Vu8xP.png\"}},\"gkxData\":{\"4112\":{\"result\":false,\"hash\":null},\"5943\":{\"result\":false,\"hash\":null},\"7685\":{\"result\":false,\"hash\":null},\"10314\":{\"result\":false,\"hash\":null},\"16915\":{\"result\":false,\"hash\":null},\"16928\":{\"result\":false,\"hash\":null},\"17038\":{\"result\":false,\"hash\":null},\"26256\":{\"result\":false,\"hash\":null},\"26258\":{\"result\":true,\"hash\":null},\"26259\":{\"result\":false,\"hash\":null}},\"justknobxData\":{\"371\":{\"r\":true},\"1050\":{\"r\":false},\"1617\":{\"r\":165},\"1618\":{\"r\":8},\"1619\":{\"r\":1},\"1620\":{\"r\":2},\"1621\":{\"r\":4},\"1622\":{\"r\":0},\"1623\":{\"r\":6},\"1624\":{\"r\":1},\"1662\":{\"r\":2},\"1663\":{\"r\":14},\"1664\":{\"r\":2},\"1854\":{\"r\":false},\"2237\":{\"r\":false},\"2337\":{\"r\":false},\"2517\":{\"r\":true},\"3717\":{\"r\":1},\"4952\":{\"r\":true}}}}}");

      if (self.trustedTypes && self.trustedTypes.createPolicy) {
        const escapeScriptURLPolicy = self.trustedTypes.createPolicy("workerPolicy", {
          createScriptURL: url => url
        });
        importScripts(escapeScriptURLPolicy.createScriptURL("https:\/\/static.whatsapp.net\/rsrc.php\/v4\/yq\/r\/odrxy-7zVX8.js"));
      } else {
         importScripts("https:\/\/static.whatsapp.net\/rsrc.php\/v4\/yq\/r\/odrxy-7zVX8.js");
      }"#;

        assert_eq!(parse_sw_js(s), Some((2, 3000, 1026131876)));
    }
}
