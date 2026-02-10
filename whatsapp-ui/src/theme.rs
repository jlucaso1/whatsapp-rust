//! WhatsApp theme colors and layout constants
//!
//! This module provides static theme constants. For responsive layout dimensions
//! that adapt to screen size, use the `responsive` module instead.

/// WhatsApp-specific colors
pub mod colors {
    pub const ACCENT_GREEN: u32 = 0x00a884;
    #[allow(dead_code)]
    pub const ACCENT_BLUE: u32 = 0x53bdeb;

    pub const BG_MESSAGE_SENT: u32 = 0x005c4b;
    pub const BG_MESSAGE_RECEIVED: u32 = 0x202c33;

    pub const BG_PRIMARY: u32 = 0x111b21;
    pub const BG_SECONDARY: u32 = 0x202c33;
    pub const BG_CHAT: u32 = 0x0b141a;
    pub const BG_HOVER: u32 = 0x2a3942;
    pub const BG_SELECTED: u32 = 0x374248;

    pub const TEXT_PRIMARY: u32 = 0xe9edef;
    pub const TEXT_SECONDARY: u32 = 0x8696a0;

    pub const BORDER: u32 = 0x2a3942;
    pub const ERROR: u32 = 0xff4444;
    pub const WHITE: u32 = 0xffffff;
    pub const BLACK: u32 = 0x000000;
}

/// Static layout constants (non-responsive)
///
/// For dimensions that should adapt to screen size, use `ResponsiveLayout` instead.
/// These constants are for fixed-size elements.
pub mod layout {
    // Used by InputAreaView (doesn't receive ResponsiveLayout)
    pub const INPUT_AREA_HEIGHT: f32 = 62.0;

    // Fixed-size elements
    pub const QR_CODE_SIZE: f32 = 256.0;
    pub const RADIUS_SMALL: f32 = 4.0;
    pub const RADIUS_MEDIUM: f32 = 8.0;
    pub const RADIUS_LARGE: f32 = 20.0;

    // Message bubble constants
    pub const MSG_PADDING_TOP_FIRST: f32 = 8.0;
    pub const MSG_PADDING_TOP_GROUPED: f32 = 6.0;
    pub const MSG_PADDING_BOTTOM: f32 = 4.0;
    pub const MSG_BUBBLE_PADDING_Y: f32 = 8.0;
    pub const MSG_BUBBLE_PADDING_X: f32 = 12.0;
    pub const MSG_CONTENT_GAP: f32 = 4.0;
    pub const MSG_TEXT_LINE_HEIGHT: f32 = 22.0;
    pub const MSG_TIME_ROW_HEIGHT: f32 = 24.0;
    pub const MSG_SENDER_NAME_HEIGHT: f32 = 22.0;
    pub const MSG_REACTION_MARGIN_TOP: f32 = 4.0;
    pub const MSG_REACTION_HEIGHT: f32 = 28.0;
}
