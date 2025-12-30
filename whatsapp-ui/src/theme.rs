//! WhatsApp dark theme colors and constants

use gpui::rgb;

/// WhatsApp dark theme colors
pub mod colors {
    /// Primary background (main app background)
    pub const BG_PRIMARY: u32 = 0x111b21;
    /// Secondary background (sidebar, headers)
    pub const BG_SECONDARY: u32 = 0x202c33;
    /// Chat area background
    pub const BG_CHAT: u32 = 0x0b141a;
    /// Primary text color
    pub const TEXT_PRIMARY: u32 = 0xe9edef;
    /// Secondary/muted text color
    pub const TEXT_SECONDARY: u32 = 0x8696a0;
    /// WhatsApp green accent
    pub const ACCENT_GREEN: u32 = 0x00a884;
    /// Blue accent (links, etc)
    #[allow(dead_code)]
    pub const ACCENT_BLUE: u32 = 0x53bdeb;
    /// Sent message bubble background
    pub const BG_MESSAGE_SENT: u32 = 0x005c4b;
    /// Received message bubble background
    pub const BG_MESSAGE_RECEIVED: u32 = 0x202c33;
    /// Border/divider color
    pub const BORDER: u32 = 0x2a3942;
    /// Hover background (slightly lighter than BG_SECONDARY)
    pub const BG_HOVER: u32 = 0x2a3942;
    /// Selected item background (slightly lighter than hover for clear selection)
    pub const BG_SELECTED: u32 = 0x374248;
    /// Error/danger color
    pub const ERROR: u32 = 0xff4444;
    /// White
    pub const WHITE: u32 = 0xffffff;
    /// Black
    pub const BLACK: u32 = 0x000000;
}

/// Layout constants
pub mod layout {
    /// Sidebar width
    pub const SIDEBAR_WIDTH: f32 = 350.0;
    /// Header height
    pub const HEADER_HEIGHT: f32 = 60.0;
    /// Chat item height
    pub const CHAT_ITEM_HEIGHT: f32 = 72.0;
    /// Input area height
    pub const INPUT_AREA_HEIGHT: f32 = 62.0;
    /// Avatar size (large)
    pub const AVATAR_SIZE_LARGE: f32 = 48.0;
    /// Avatar size (medium)
    pub const AVATAR_SIZE_MEDIUM: f32 = 40.0;
    /// Max message bubble width
    pub const MAX_BUBBLE_WIDTH: f32 = 400.0;
    /// Max media display size
    pub const MAX_MEDIA_SIZE: f32 = 300.0;
    /// QR code display size
    pub const QR_CODE_SIZE: f32 = 256.0;
    /// Border radius (small)
    pub const RADIUS_SMALL: f32 = 4.0;
    /// Border radius (medium)
    pub const RADIUS_MEDIUM: f32 = 8.0;
    /// Border radius (large/pill)
    pub const RADIUS_LARGE: f32 = 20.0;

    // === Message bubble constants (shared between render and height calculation) ===

    /// Outer message row padding - top (first message or different sender)
    pub const MSG_PADDING_TOP_FIRST: f32 = 8.0;
    /// Outer message row padding - top (grouped/consecutive from same sender)
    pub const MSG_PADDING_TOP_GROUPED: f32 = 6.0;
    /// Outer message row padding - bottom
    pub const MSG_PADDING_BOTTOM: f32 = 4.0;
    /// Bubble internal padding (vertical, py_2)
    pub const MSG_BUBBLE_PADDING_Y: f32 = 8.0;
    /// Bubble internal padding (horizontal, px_3)
    pub const MSG_BUBBLE_PADDING_X: f32 = 12.0;
    /// Gap between elements inside bubble (gap_1)
    pub const MSG_CONTENT_GAP: f32 = 4.0;
    /// Text line height (normal text)
    pub const MSG_TEXT_LINE_HEIGHT: f32 = 22.0;
    /// Time row height (includes copy button touch target)
    pub const MSG_TIME_ROW_HEIGHT: f32 = 24.0;
    /// Sender name height in groups
    pub const MSG_SENDER_NAME_HEIGHT: f32 = 22.0;
    /// Reaction row margin top
    pub const MSG_REACTION_MARGIN_TOP: f32 = 4.0;
    /// Reaction pill height (emoji + padding)
    pub const MSG_REACTION_HEIGHT: f32 = 28.0;
}

/// Get a gpui Rgba color from a hex constant
#[allow(dead_code)]
#[inline]
pub fn color(hex: u32) -> gpui::Rgba {
    rgb(hex)
}
