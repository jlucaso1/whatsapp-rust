use chrono::Local;
use log::{debug, error};
use tokio::task;
use wacore::proto_helpers::MessageExt;
use whatsapp_rust::bot::Bot;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
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
        .unwrap();

    let local = task::LocalSet::new();

    local.block_on(&rt, async {
        Bot::builder()
            .on_message(|ctx| async move {
                if let Some(text) = ctx.message.text_content()
                    && text == "ping"
                {
                    debug!("Received ping, sending pong...");
                    if let Err(e) = ctx.reply("pong").await {
                        error!("Failed to send reply: {}", e);
                    }
                }
            })
            .run()
            .await;
    });
}
