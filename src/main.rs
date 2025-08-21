use chrono::Local;
use log::{debug, error, info};
use std::io::Cursor;
use tokio::task;
use wacore::download::MediaType;
use wacore::proto_helpers::MessageExt;
use waproto::whatsapp as wa;
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
                let base_message = ctx.message.get_base_message();

                if let Some(image_msg) = &base_message.image_message
                    && image_msg.caption.as_deref() == Some("ping")
                {
                    info!("Received image ping from {}", ctx.info.source.sender);

                    let mut image_data_buffer = Cursor::new(Vec::new());
                    match ctx
                        .client
                        .download_to_file(&**image_msg, &mut image_data_buffer)
                        .await
                    {
                        Ok(_) => {
                            info!(
                                "Successfully downloaded image. Size: {} bytes. Now uploading...",
                                image_data_buffer.get_ref().len()
                            );
                            let plaintext_data = image_data_buffer.into_inner();
                            match ctx.client.upload(plaintext_data, MediaType::Image).await {
                                Ok(upload_response) => {
                                    info!(
                                        "Successfully uploaded image. Constructing reply message..."
                                    );

                                    let reply_image_msg = wa::message::ImageMessage {
                                        mimetype: image_msg.mimetype.clone(),
                                        caption: Some("pong".to_string()),
                                        url: Some(upload_response.url),
                                        direct_path: Some(upload_response.direct_path),
                                        media_key: Some(upload_response.media_key),
                                        file_enc_sha256: Some(upload_response.file_enc_sha256),
                                        file_sha256: Some(upload_response.file_sha256),
                                        file_length: Some(upload_response.file_length),
                                        ..Default::default()
                                    };

                                    let reply_msg = wa::Message {
                                        image_message: Some(Box::new(reply_image_msg)),
                                        ..Default::default()
                                    };

                                    if let Err(e) = ctx.send_message(reply_msg).await {
                                        error!("Failed to send image pong reply: {}", e);
                                    } else {
                                        info!("Image pong reply sent successfully.");
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to upload image: {}", e);
                                    let _ = ctx.reply("Failed to re-upload the image.").await;
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to download image: {}", e);
                            let _ = ctx.reply("Failed to download your image.").await;
                        }
                    }
                }

                if let Some(text) = ctx.message.text_content()
                    && text == "ping"
                {
                    debug!("Received text ping, sending pong...");
                    if let Err(e) = ctx.reply("pong").await {
                        error!("Failed to send text reply: {}", e);
                    }
                }
            })
            .run()
            .await;
    });
}
