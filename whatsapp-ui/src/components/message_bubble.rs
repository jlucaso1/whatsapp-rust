//! Message bubble component for displaying chat messages

use std::collections::HashMap;
use std::sync::Arc;

use gpui::{
    Entity, Image, ImageSource, ObjectFit, SharedString, YuvFrameData, div, img, prelude::*, px,
    rgb, surface,
};
use gpui_component::button::{Button, ButtonVariants};
use gpui_component::clipboard::Clipboard;
use gpui_component::h_flex;
use gpui_component::v_flex;
use gpui_component::{Disableable, Icon};

use crate::app::WhatsAppApp;
use crate::state::{ChatMessage, MediaType};
use crate::theme::{colors, layout};
use crate::utils::{format_time_local, mime_to_image_format};
use crate::video::VideoPlayerState;

/// Render a single message bubble
/// Takes owned ChatMessage since virtual list callback needs owned elements
///
/// Parameters:
/// - `message`: The message to render
/// - `entity`: The app entity for callbacks
/// - `playing_message_id`: Currently playing audio message ID (if any)
/// - `is_group`: Whether this is a group chat (to show sender names)
/// - `show_sender`: Whether to show sender name (false if previous message was from same sender)
/// - `video_player_state`: Current video player state for this message (if any)
/// - `video_frame`: Current video frame as YuvFrameData (GPU-accelerated YUV rendering)
/// - `sticker_image`: Cached sticker image for animation state preservation
pub fn render_message_bubble(
    message: ChatMessage,
    entity: Entity<WhatsAppApp>,
    playing_message_id: Option<String>,
    is_group: bool,
    show_sender: bool,
    video_player_state: Option<VideoPlayerState>,
    video_frame: Option<YuvFrameData>,
    sticker_image: Option<Arc<Image>>,
) -> impl IntoElement {
    let is_from_me = message.is_from_me;
    let message_id = message.id.clone();
    // Use SharedString to avoid allocation for text content
    let content: SharedString = message.content.clone().into();
    let time: SharedString = format_time_local(&message.timestamp).into();
    // Clone the Arc, not the underlying data - this is cheap
    let media = message.media.clone();
    // Clone content for clipboard
    let content_for_copy = message.content.clone();
    // Create a unique ID for the bubble
    let bubble_id: SharedString = format!("msg-{}", message.id).into();
    // Check if this message is currently playing
    let is_playing = playing_message_id.as_ref() == Some(&message_id);
    // Clone reactions for rendering
    let reactions = message.reactions.clone();
    let has_reactions = !reactions.is_empty();
    // Get sender name for group messages
    let sender_name: Option<SharedString> = if is_group && !is_from_me && show_sender {
        message.sender_name.clone().map(|s| s.into())
    } else {
        None
    };

    div()
        .w_full()
        .flex()
        .when(is_from_me, |el| el.justify_end())
        .when(!is_from_me, |el| el.justify_start())
        // Reduce padding when grouping consecutive messages
        .when(show_sender, |el| el.pt(px(layout::MSG_PADDING_TOP_FIRST)))
        .when(!show_sender, |el| {
            el.pt(px(layout::MSG_PADDING_TOP_GROUPED))
        })
        .pb(px(layout::MSG_PADDING_BOTTOM))
        .child(
            v_flex()
                .items_end()
                .when(!is_from_me, |el| el.items_start())
                .child(
                    div()
                        .id(bubble_id.clone())
                        .max_w(px(layout::MAX_BUBBLE_WIDTH))
                        .px(px(layout::MSG_BUBBLE_PADDING_X))
                        .py(px(layout::MSG_BUBBLE_PADDING_Y))
                        .rounded(px(layout::RADIUS_MEDIUM))
                        .bg(if is_from_me {
                            rgb(colors::BG_MESSAGE_SENT)
                        } else {
                            rgb(colors::BG_MESSAGE_RECEIVED)
                        })
                        .child(
                            v_flex()
                                .gap(px(layout::MSG_CONTENT_GAP))
                                // Show sender name for group messages (when not grouped)
                                .when_some(sender_name, |el, name| {
                                    el.child(
                                        div()
                                            .text_sm()
                                            .font_weight(gpui::FontWeight::SEMIBOLD)
                                            .text_color(rgb(colors::ACCENT_GREEN))
                                            .child(name),
                                    )
                                })
                                // Render media if present
                                .when_some(media, |el, media_content| {
                                    render_media_content(
                                        el,
                                        media_content,
                                        message_id.clone(),
                                        is_playing,
                                        entity.clone(),
                                        video_player_state,
                                        video_frame.clone(),
                                        sticker_image.clone(),
                                    )
                                })
                                .when(!content.is_empty(), |el| {
                                    el.child(
                                        div()
                                            .overflow_hidden()
                                            .text_color(rgb(colors::TEXT_PRIMARY))
                                            .child(content),
                                    )
                                })
                                // Time and copy button row
                                .child(
                                    div()
                                        .flex()
                                        .items_center()
                                        .justify_between()
                                        .gap_2()
                                        .child(
                                            div()
                                                .text_color(rgb(colors::TEXT_SECONDARY))
                                                .text_xs()
                                                .child(time),
                                        )
                                        // Copy button - only show if there's text content
                                        .when(!content_for_copy.is_empty(), |el| {
                                            el.child(
                                                Clipboard::new(bubble_id).value(content_for_copy),
                                            )
                                        }),
                                ),
                        ),
                )
                // Render reactions below the bubble
                .when(has_reactions, |el| {
                    el.child(render_reactions(reactions, is_from_me))
                }),
        )
}

/// Render reactions row below a message bubble
fn render_reactions(reactions: HashMap<String, Vec<String>>, is_from_me: bool) -> impl IntoElement {
    // Sort reactions by count (most popular first), then alphabetically
    let mut sorted_reactions: Vec<_> = reactions.into_iter().collect();
    sorted_reactions.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));

    h_flex()
        .gap_1()
        .mt(px(layout::MSG_REACTION_MARGIN_TOP))
        .h(px(layout::MSG_REACTION_HEIGHT))
        .when(is_from_me, |el| el.justify_end())
        .when(!is_from_me, |el| el.justify_start())
        .px_1()
        .children(sorted_reactions.into_iter().map(|(emoji, senders)| {
            let count = senders.len();
            let emoji_str: SharedString = emoji.into();

            div()
                .px(px(6.))
                .py(px(2.))
                .rounded(px(12.))
                .bg(rgb(colors::BG_SELECTED))
                .border_1()
                .border_color(rgb(colors::BORDER))
                .flex()
                .items_center()
                .gap(px(2.))
                .child(div().text_sm().child(emoji_str))
                .when(count > 1, |el| {
                    el.child(
                        div()
                            .text_xs()
                            .text_color(rgb(colors::TEXT_SECONDARY))
                            .child(count.to_string()),
                    )
                })
        }))
}

/// Render media content within a message bubble
fn render_media_content(
    el: gpui::Div,
    media_content: crate::state::MediaContent,
    message_id: String,
    is_playing: bool,
    entity: Entity<WhatsAppApp>,
    video_player_state: Option<VideoPlayerState>,
    video_frame: Option<YuvFrameData>,
    sticker_image: Option<Arc<Image>>,
) -> gpui::Div {
    match media_content.media_type {
        MediaType::Image => {
            // Calculate display size (max 300px, maintain aspect ratio)
            let (display_w, display_h) = calculate_media_size(
                media_content.width.unwrap_or(300),
                media_content.height.unwrap_or(300),
            );

            // Only render if we have actual image data
            if !media_content.data.is_empty() {
                el.child(render_image_from_bytes(
                    media_content.data,
                    &media_content.mime_type,
                    display_w,
                    display_h,
                    true, // rounded corners
                ))
            } else {
                el.child(render_media_placeholder("[Image]", 200.0, 150.0))
            }
        }
        MediaType::Sticker => {
            // Calculate display size (max 300px, maintain aspect ratio)
            let (display_w, display_h) = calculate_media_size(
                media_content.width.unwrap_or(300),
                media_content.height.unwrap_or(300),
            );

            // Use cached sticker image if available (preserves animation state across renders)
            if let Some(cached_image) = sticker_image {
                let sticker_id: SharedString = format!("sticker-{}", message_id).into();

                // For animated stickers, GPUI handles animation automatically
                // The ID is important for GPUI to track animation state
                // The same Arc<Image> must be reused for animation to work
                el.child(
                    img(ImageSource::Image(cached_image))
                        .id(sticker_id)
                        .w(px(display_w))
                        .h(px(display_h))
                        .object_fit(gpui::ObjectFit::Contain),
                )
            } else if !media_content.data.is_empty() {
                // Fallback: create image inline (won't animate properly)
                el.child(render_image_from_bytes(
                    media_content.data,
                    &media_content.mime_type,
                    display_w,
                    display_h,
                    false, // no rounded corners for stickers
                ))
            } else {
                el.child(render_media_placeholder("[Sticker]", 150.0, 150.0))
            }
        }
        MediaType::Video => el.child(render_video_player(
            media_content,
            message_id,
            entity,
            video_player_state,
            video_frame,
        )),
        MediaType::Audio => el.child(render_audio_player(
            media_content,
            message_id,
            is_playing,
            entity,
        )),
        MediaType::Document => el.child(render_document_placeholder()),
    }
}

/// Calculate display size maintaining aspect ratio
fn calculate_media_size(width: u32, height: u32) -> (f32, f32) {
    let w = width as f32;
    let h = height as f32;
    let max_size = layout::MAX_MEDIA_SIZE;
    let scale = (max_size / w).min(max_size / h).min(1.0);
    ((w * scale).max(50.0), (h * scale).max(50.0))
}

/// Render a placeholder for unsupported media
fn render_media_placeholder(text: &'static str, width: f32, height: f32) -> impl IntoElement {
    div()
        .w(px(width))
        .h(px(height))
        .bg(rgb(colors::BG_SELECTED))
        .rounded(px(layout::RADIUS_SMALL))
        .flex()
        .justify_center()
        .items_center()
        .child(div().text_color(rgb(colors::TEXT_SECONDARY)).child(text))
}

/// Render an image from raw bytes with the given dimensions
fn render_image_from_bytes(
    data: Arc<Vec<u8>>,
    mime_type: &str,
    width: f32,
    height: f32,
    rounded: bool,
) -> gpui::Img {
    let format = mime_to_image_format(mime_type);
    let image_data = Arc::unwrap_or_clone(data);
    let image = Image::from_bytes(format, image_data);

    let img_el = img(ImageSource::Image(Arc::new(image)))
        .w(px(width))
        .h(px(height))
        .object_fit(gpui::ObjectFit::Contain);

    if rounded {
        img_el.rounded(px(layout::RADIUS_SMALL))
    } else {
        img_el
    }
}

/// Audio player state for UI rendering
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AudioPlayerState {
    #[default]
    Idle,
    Downloading,
    Playing,
    Error,
}

/// Render an audio player with play/pause button (supports lazy loading)
fn render_audio_player(
    media_content: crate::state::MediaContent,
    message_id: String,
    is_playing: bool,
    entity: Entity<WhatsAppApp>,
) -> impl IntoElement {
    let has_data = media_content.has_data();
    let can_download = media_content.can_download();
    let can_play = has_data || can_download;
    let downloadable = media_content.downloadable.clone();
    let button_id: SharedString = format!("play-{}", message_id).into();

    // Format duration if available
    let duration_text: SharedString = if let Some(secs) = media_content.duration_secs {
        let mins = secs / 60;
        let secs = secs % 60;
        format!("{:02}:{:02}", mins, secs).into()
    } else {
        "Voice message".into()
    };

    div()
        .w(px(220.))
        .h(px(44.))
        .bg(rgb(colors::BG_SELECTED))
        .rounded(px(layout::RADIUS_LARGE))
        .flex()
        .items_center()
        .px_2()
        .gap_2()
        // Play/Pause button
        .child(
            Button::new(button_id)
                .icon(if is_playing {
                    Icon::default()
                        .path("icons/pause.svg")
                        .text_color(rgb(colors::TEXT_PRIMARY))
                } else {
                    Icon::default()
                        .path("icons/play.svg")
                        .text_color(rgb(colors::TEXT_PRIMARY))
                })
                .ghost()
                .disabled(!can_play)
                .on_click({
                    let data = media_content.data.clone();
                    let downloadable = downloadable.clone();
                    move |_, _window, cx| {
                        let msg_id = message_id.clone();
                        entity.update(cx, |app, cx| {
                            if !data.is_empty() {
                                // Already have data, play directly
                                app.toggle_audio(msg_id, (*data).clone(), cx);
                            } else if let Some(dl) = downloadable.clone() {
                                // Need to download first
                                app.toggle_audio_lazy(msg_id, dl, cx);
                            }
                        });
                    }
                }),
        )
        // Waveform placeholder / progress indicator
        .child(
            div()
                .flex_1()
                .h(px(24.))
                .rounded(px(4.))
                .bg(rgb(if is_playing {
                    colors::ACCENT_GREEN
                } else {
                    colors::BG_HOVER
                }))
                .flex()
                .items_center()
                .justify_center()
                .child(
                    div()
                        .text_xs()
                        .text_color(rgb(colors::TEXT_SECONDARY))
                        .child(if is_playing {
                            SharedString::from("Playing...")
                        } else if !has_data && can_download {
                            SharedString::from("Tap to download")
                        } else {
                            duration_text
                        }),
                ),
        )
}

/// Render a document placeholder
fn render_document_placeholder() -> impl IntoElement {
    div()
        .w(px(200.))
        .h(px(50.))
        .bg(rgb(colors::BG_SELECTED))
        .rounded(px(layout::RADIUS_MEDIUM))
        .flex()
        .items_center()
        .px_3()
        .gap_2()
        .child(
            div()
                .text_color(rgb(colors::TEXT_SECONDARY))
                .child("Document"),
        )
}

/// Render a video player with play button overlay
fn render_video_player(
    media_content: crate::state::MediaContent,
    message_id: String,
    entity: Entity<WhatsAppApp>,
    video_player_state: Option<VideoPlayerState>,
    video_frame: Option<YuvFrameData>,
) -> impl IntoElement {
    // Calculate display size (max 300px, maintain aspect ratio)
    let (display_w, display_h) = calculate_media_size(
        media_content.width.unwrap_or(300),
        media_content.height.unwrap_or(200),
    );

    let button_id: SharedString = format!("video-{}", message_id).into();
    let state = video_player_state.unwrap_or(VideoPlayerState::Idle);
    let downloadable = media_content.downloadable.clone();
    let can_download = media_content.can_download();

    // Use state helper methods
    let is_playing = state.is_playing();
    let is_paused = state.is_paused();
    let is_loading = state.is_loading();
    let is_error = state.is_error();

    div()
        .relative()
        .w(px(display_w))
        .h(px(display_h))
        .rounded(px(layout::RADIUS_SMALL))
        .overflow_hidden()
        .child(
            // Background: either video frame or thumbnail
            if let Some(frame) = video_frame.filter(|_| is_playing || is_paused) {
                // Render current video frame using YUV surface (GPU-accelerated)
                // YUV→RGB conversion happens on GPU - no CPU overhead
                div()
                    .w_full()
                    .h_full()
                    .child(
                        surface(frame)
                            .w(px(display_w))
                            .h(px(display_h))
                            .object_fit(ObjectFit::Contain),
                    )
                    .into_any_element()
            } else if !media_content.data.is_empty() {
                // Render thumbnail
                div()
                    .w_full()
                    .h_full()
                    .child(render_image_from_bytes(
                        media_content.data,
                        &media_content.mime_type,
                        display_w,
                        display_h,
                        false, // no rounded corners (container handles it)
                    ))
                    .into_any_element()
            } else {
                // No thumbnail available
                div()
                    .w_full()
                    .h_full()
                    .bg(rgb(colors::BG_SELECTED))
                    .flex()
                    .justify_center()
                    .items_center()
                    .child(
                        div()
                            .text_color(rgb(colors::TEXT_SECONDARY))
                            .child("[Video]"),
                    )
                    .into_any_element()
            },
        )
        // Overlay with play/pause button
        .child(
            div()
                .absolute()
                .inset_0()
                .flex()
                .justify_center()
                .items_center()
                .bg(gpui::rgba(0x00000066)) // Semi-transparent overlay
                .when(!is_playing, |el| el)
                .when(is_playing, |el| el.bg(gpui::rgba(0x00000000))) // No overlay when playing
                .child(if is_loading {
                    // Show loading indicator
                    div()
                        .w(px(48.))
                        .h(px(48.))
                        .rounded_full()
                        .bg(gpui::rgba(0x00000088))
                        .flex()
                        .justify_center()
                        .items_center()
                        .child(div().text_color(rgb(colors::TEXT_PRIMARY)).text_sm().child(
                            if state == VideoPlayerState::Downloading {
                                "↓"
                            } else {
                                "⏳"
                            },
                        ))
                        .into_any_element()
                } else if is_error {
                    // Show error indicator
                    div()
                        .w(px(48.))
                        .h(px(48.))
                        .rounded_full()
                        .bg(gpui::rgba(0xFF000088))
                        .flex()
                        .justify_center()
                        .items_center()
                        .child(
                            div()
                                .text_color(rgb(colors::TEXT_PRIMARY))
                                .text_sm()
                                .child("⚠"),
                        )
                        .into_any_element()
                } else if !is_playing {
                    // Show play button
                    Button::new(button_id)
                        .icon(
                            Icon::default()
                                .path("icons/play.svg")
                                .text_color(rgb(colors::TEXT_PRIMARY))
                                .size(px(32.)),
                        )
                        .ghost()
                        .disabled(!can_download)
                        .on_click({
                            let downloadable = downloadable.clone();
                            move |_, _window, cx| {
                                if let Some(dl) = downloadable.clone() {
                                    let msg_id = message_id.clone();
                                    entity.update(cx, |app, cx| {
                                        app.toggle_video(msg_id, dl, cx);
                                    });
                                }
                            }
                        })
                        .into_any_element()
                } else {
                    // Playing - show pause button on hover (subtle)
                    Button::new(button_id)
                        .icon(
                            Icon::default()
                                .path("icons/pause.svg")
                                .text_color(gpui::rgba(0xFFFFFF66))
                                .size(px(24.)),
                        )
                        .ghost()
                        .on_click({
                            let downloadable = downloadable.clone();
                            move |_, _window, cx| {
                                if let Some(dl) = downloadable.clone() {
                                    let msg_id = message_id.clone();
                                    entity.update(cx, |app, cx| {
                                        app.toggle_video(msg_id, dl, cx);
                                    });
                                }
                            }
                        })
                        .into_any_element()
                }),
        )
}
