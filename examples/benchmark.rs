use chrono::Local;
use log::{error, info};
use std::sync::Arc;
use wacore::proto_helpers::MessageExt;
use wacore::store::InMemoryBackend;
use wacore::types::events::Event;
use waproto::whatsapp as wa;
use whatsapp_rust::TokioRuntime;
use whatsapp_rust::bot::{Bot, MessageContext};
use whatsapp_rust_tokio_transport::TokioWebSocketTransportFactory;
use whatsapp_rust_ureq_http_client::UreqHttpClient;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .format(|buf, record| {
            use std::io::Write;
            writeln!(
                buf,
                "{} [{:<5}] [{}] - {}",
                Local::now().format("%H:%M:%S"),
                record.level(),
                record.target(),
                record.args()
            )
        })
        .init();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to build tokio runtime");

    rt.block_on(async {
        let backend = Arc::new(InMemoryBackend::new().with_sent_message_ttl(30));

        let mut transport_factory = TokioWebSocketTransportFactory::new();
        if let Ok(ws_url) = std::env::var("WHATSAPP_WS_URL") {
            transport_factory = transport_factory.with_url(ws_url);
        }
        let http_client = UreqHttpClient::new();

        let builder = Bot::builder()
            .with_backend(backend)
            .with_transport_factory(transport_factory)
            .with_http_client(http_client)
            .with_runtime(TokioRuntime);

        let mut bot = builder
            .on_event(move |event, client| async move {
                match &*event {
                    Event::Message(msg, info) => {
                        if let Some(text) = msg.text_content()
                            && text == "ping"
                        {
                            let ctx = MessageContext::from_parts(msg, info, client);
                            info!("Received text ping, sending pong...");

                            let pong_text = format!("pong {}", ctx.info.id);
                            let reply_message = wa::Message {
                                conversation: Some(pong_text),
                                ..Default::default()
                            };

                            if let Err(e) = ctx.send_message(reply_message).await {
                                error!("Failed to send pong reply: {}", e);
                            }
                        }
                    }
                    Event::Connected(_) => {
                        info!("✅ Bot connected successfully!");
                    }
                    Event::LoggedOut(_) => {
                        error!("❌ Bot was logged out!");
                    }
                    _ => {}
                }
            })
            .build()
            .await
            .expect("Failed to build bot");

        let bot_handle = match bot.run().await {
            Ok(handle) => handle,
            Err(e) => {
                error!("Bot failed to start: {}", e);
                return;
            }
        };

        bot_handle
            .await
            .expect("Bot task should complete without panicking");
    });
}
