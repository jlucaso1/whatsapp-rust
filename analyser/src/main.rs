use chromiumoxide::{
    browser::{Browser, BrowserConfig},
    cdp::js_protocol::runtime,
};
use futures::StreamExt;

const MONKEY_PATCH_SCRIPT: &str = r#"
(() => {
    console.log('[ANALYZER] Attempting to inject monkey-patches...');

    const jsonReplacer = (key, value) => {
        if (value instanceof Uint8Array) {
            return `Uint8Array(len=${value.length})`;
        }
        if (typeof value === 'object' && value !== null) {
            if (value.type === 'Buffer' && Array.isArray(value.data)) {
                return `Buffer(len=${value.data.length})`;
            }
        }
        return value;
    };

    // --- Patch 1: decodeProtobuf ---
    try {
        if (window.decodeProtobufPatched) throw new Error("Already patched");
        const originalDecodeProtobuf = require("decodeProtobuf").decodeProtobuf;
        require("decodeProtobuf").decodeProtobuf = (a, b) => {
            const result = originalDecodeProtobuf(a, b);
            console.log('[DECODE]', JSON.stringify(result, jsonReplacer, 2));
            return result;
        };
        window.decodeProtobufPatched = true;
        console.log('[ANALYZER] Monkey-patch for decodeProtobuf injected successfully!');
    } catch (e) {
        console.error('[ANALYZER] Failed to patch decodeProtobuf:', e.message);
    }

    // --- Patch 2: encodeAndPad (for sending messages) ---
    try {
        if (window.encodeAndPadPatched) throw new Error("Already patched");
        if(!window.encodeBack) {
            window.encodeBack = require("WAWebSendMsgCommonApi").encodeAndPad;
        }
        require("WAWebSendMsgCommonApi").encodeAndPad = (a) => {
            const result = window.encodeBack(a);
            console.log('[ENCODE]', JSON.stringify(a, jsonReplacer, 2));
            return result;
        };
        window.encodeAndPadPatched = true;
        console.log('[ANALYZER] Monkey-patch for encodeAndPad injected successfully!');
    } catch(e) {
        console.error('[ANALYZER] Failed to patch encodeAndPad:', e.message);
    }

    // --- Patch 3: encodeStanza (for sending stanzas) ---
    try {
        if (window.encodeStanzaPatched) throw new Error("Already patched");
        if (!window.encodeBackStanza) {
            window.encodeBackStanza = require("WAWap").encodeStanza;
        }
        require("WAWap").encodeStanza = (...args) => {
            const result = window.encodeBackStanza(...args);
            console.log('[SENT]', JSON.stringify(args[0], jsonReplacer, 2));
            return result;
        };
        window.encodeStanzaPatched = true;
        console.log('[ANALYZER] Monkey-patch for encodeStanza injected successfully!');
    } catch(e) {
        console.error('[ANALYZER] Failed to patch encodeStanza:', e.message);
    }

    // --- Patch 4: decodeStanza (for receiving stanzas) ---
    try {
        if (window.decodeStanzaPatched) throw new Error("Already patched");
        if (!window.decodeBackStanza) {
            window.decodeBackStanza = require("WAWap").decodeStanza;
        }
        require("WAWap").decodeStanza = async (e, t) => {
            const result = await window.decodeBackStanza(e, t);
            console.log('[RECEIVED]', JSON.stringify(result, jsonReplacer, 2));
            return result;
        };
        window.decodeStanzaPatched = true;
        console.log('[ANALYZER] Monkey-patch for decodeStanza injected successfully!');
    } catch(e) {
        console.error('[ANALYZER] Failed to patch decodeStanza:', e.message);
    }

    // --- Patch 5: buildSyncIqNode (for app state sync) ---
    try {
        if (window.buildSyncIqNodePatched) throw new Error("Already patched");
        if(!window.syncIqBack){
            window.syncIqBack = require("WAWebSyncdRequestBuilderBuild").buildSyncIqNode;
        }
        require("WAWebSyncdRequestBuilderBuild").buildSyncIqNode = (a) => {
            const result = window.syncIqBack(a);
            try {
                const values = Array.from(a.values()).flat();
                const decodedValues = values.map(v => {
                    const newV = { ...v };
                    newV.binarySyncAction = require("decodeProtobuf").decodeProtobuf(
                        require("WASyncAction.pb").SyncActionValueSpec,
                        v.binarySyncAction
                    );
                    return newV;
                });
                console.log('[APP STATE MUTATION]', JSON.stringify(decodedValues, jsonReplacer, 2));
            } catch (err) {
                console.log('[APP STATE MUTATION] ERROR', `Failed to decode: ${err.message}. Original data:`, JSON.stringify(a, jsonReplacer, 2));
            }
            return result;
        };
        window.buildSyncIqNodePatched = true;
        console.log('[ANALYZER] Monkey-patch for buildSyncIqNode injected successfully!');
    } catch(e) {
        console.error('[ANALYZER] Failed to patch buildSyncIqNode:', e.message);
    }

    console.log('[ANALYZER] All monkey-patch attempts finished.');
})();
"#;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    log::info!("Starting WhatsApp Logger...");

    let config = BrowserConfig::builder()
        .user_data_dir("./.profile")
        .chrome_executable("/sbin/google-chrome-stable")
        .with_head()
        .build()
        .expect("Failed to build browser config");

    let (browser, mut handler) = Browser::launch(config).await?;

    let handle = tokio::spawn(async move {
        while let Some(h) = handler.next().await {
            if let Err(err) = h {
                log::debug!("Browser handler error: {err}");
            }
        }
    });

    let page = browser.new_page("https://web.whatsapp.com/").await?;
    log::info!("Navigated to WhatsApp Web. Waiting for the page to load...");
    log::info!("Please scan the QR code if needed.");

    let wait_for_element_js = r#"
        new Promise((resolve, reject) => {
            const selector = "canvas[aria-label='Scan me!'], div#app";
            const element = document.querySelector(selector);
            if (element) {
                console.log('[ANALYZER] Element found immediately.');
                return resolve(true);
            }

            const observer = new MutationObserver((mutations, obs) => {
                const element = document.querySelector(selector);
                if (element) {
                    console.log('[ANALYZER] Element appeared after mutation.');
                    obs.disconnect();
                    resolve(true);
                }
            });

            observer.observe(document.body, {
                childList: true,
                subtree: true
            });

            setTimeout(() => {
                observer.disconnect();
                reject(new Error("Timeout: Element did not appear within 30 seconds."));
            }, 30000);
        })
      "#;

    log::info!("Waiting for WhatsApp UI to become available...");
    page.evaluate(wait_for_element_js).await?;
    log::info!("WhatsApp interface detected. Injecting script...");

    page.execute(runtime::EnableParams::default()).await?;

    let mut console_events = page
        .event_listener::<runtime::EventConsoleApiCalled>()
        .await?;
    let console_task = tokio::spawn(async move {
        while let Some(event) = console_events.next().await {
            if let Some(first_arg) = event.args.first() {
                if let Some(val) = &first_arg.value {
                    if let Some(s) = val.as_str() {
                        let is_analyser_log = s.starts_with("[ANALYZER]");
                        let is_data_log = s.starts_with("[DECODE]")
                            || s.starts_with("[ENCODE]")
                            || s.starts_with("[SENT]")
                            || s.starts_with("[RECEIVED]")
                            || s.starts_with("[APP STATE MUTATION]");

                        if is_analyser_log || is_data_log {
                            let full_message = event
                                .args
                                .iter()
                                .map(|arg| {
                                    if let Some(val) = &arg.value {
                                        if let Some(s) = val.as_str() {
                                            s.to_string()
                                        } else {
                                            val.to_string()
                                        }
                                    } else {
                                        arg.description.clone().unwrap_or_default()
                                    }
                                })
                                .collect::<Vec<_>>()
                                .join(" ");

                            if is_analyser_log {
                                log::info!(target: "analyser::web", "{full_message}");
                            } else {
                                log::debug!(target: "analyser::web", "{full_message}");
                            }
                        }
                    }
                }
            }
        }
    });

    if let Err(err) = page.evaluate(MONKEY_PATCH_SCRIPT).await {
        log::error!("Failed to inject script: {err:?}");
    }

    log::info!("Script injected. Listening for logs. Press Ctrl+C to exit.");

    tokio::select! {
        _ = handle => log::info!("Browser handler finished."),
        _ = console_task => log::info!("Console listener finished."),
        _ = tokio::signal::ctrl_c() => log::info!("Ctrl+C received, shutting down."),
    }

    Ok(())
}
