use gpui::{Pixels, Size};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Breakpoint {
    Mobile,
    Tablet,
    Desktop,
}

impl Breakpoint {
    pub const MOBILE_MAX: f32 = 600.0;
    pub const TABLET_MAX: f32 = 900.0;

    pub fn from_width(width: f32) -> Self {
        if width < Self::MOBILE_MAX {
            Self::Mobile
        } else if width < Self::TABLET_MAX {
            Self::Tablet
        } else {
            Self::Desktop
        }
    }

    pub fn is_mobile(&self) -> bool {
        matches!(self, Self::Mobile)
    }

    pub fn is_tablet(&self) -> bool {
        matches!(self, Self::Tablet)
    }

    pub fn is_desktop(&self) -> bool {
        matches!(self, Self::Desktop)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MobilePanel {
    #[default]
    ChatList,
    Chat,
}

impl MobilePanel {
    pub fn is_chat_list(&self) -> bool {
        matches!(self, Self::ChatList)
    }

    pub fn is_chat(&self) -> bool {
        matches!(self, Self::Chat)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ResponsiveLayout {
    breakpoint: Breakpoint,
    mobile_panel: MobilePanel,
    viewport_width: f32,
}

impl ResponsiveLayout {
    const SIDEBAR_WIDTH_DESKTOP: f32 = 320.0;
    const SIDEBAR_WIDTH_TABLET: f32 = 240.0;
    const SIDEBAR_WIDTH_MIN: f32 = 200.0;

    const HEADER_HEIGHT: f32 = 56.0;
    const HEADER_HEIGHT_MOBILE: f32 = 52.0;

    const CHAT_ITEM_HEIGHT_DESKTOP: f32 = 72.0;
    const CHAT_ITEM_HEIGHT_TABLET: f32 = 68.0;
    const CHAT_ITEM_HEIGHT_MOBILE: f32 = 64.0;

    const AVATAR_SIZE_LARGE: f32 = 48.0;
    const AVATAR_SIZE_MOBILE: f32 = 44.0;

    const INPUT_AREA_HEIGHT: f32 = 62.0;
    const INPUT_AREA_HEIGHT_MOBILE: f32 = 56.0;

    const MAX_BUBBLE_WIDTH_DESKTOP: f32 = 400.0;
    const MAX_BUBBLE_WIDTH_TABLET: f32 = 350.0;
    const MAX_BUBBLE_WIDTH_MOBILE_RATIO: f32 = 0.85;

    const MAX_MEDIA_SIZE_DESKTOP: f32 = 300.0;
    const MAX_MEDIA_SIZE_TABLET: f32 = 280.0;
    const MAX_MEDIA_SIZE_MOBILE_RATIO: f32 = 0.75;

    pub fn new(viewport: Size<Pixels>, mobile_panel: MobilePanel) -> Self {
        let width: f32 = viewport.width.into();

        Self {
            breakpoint: Breakpoint::from_width(width),
            mobile_panel,
            viewport_width: width,
        }
    }

    pub fn breakpoint(&self) -> Breakpoint {
        self.breakpoint
    }

    pub fn is_mobile(&self) -> bool {
        self.breakpoint.is_mobile()
    }

    pub fn is_tablet(&self) -> bool {
        self.breakpoint.is_tablet()
    }

    pub fn is_desktop(&self) -> bool {
        self.breakpoint.is_desktop()
    }

    pub fn is_compact(&self) -> bool {
        self.is_mobile() || self.is_tablet()
    }

    pub fn mobile_panel(&self) -> MobilePanel {
        self.mobile_panel
    }

    pub fn show_sidebar(&self) -> bool {
        match self.breakpoint {
            Breakpoint::Desktop | Breakpoint::Tablet => true,
            Breakpoint::Mobile => self.mobile_panel.is_chat_list(),
        }
    }

    pub fn show_chat_area(&self) -> bool {
        match self.breakpoint {
            Breakpoint::Desktop | Breakpoint::Tablet => true,
            Breakpoint::Mobile => self.mobile_panel.is_chat(),
        }
    }

    pub fn show_back_button(&self) -> bool {
        self.is_mobile() && self.mobile_panel.is_chat()
    }

    pub fn show_call_buttons(&self) -> bool {
        self.viewport_width >= 400.0
    }

    pub fn sidebar_width(&self) -> f32 {
        match self.breakpoint {
            Breakpoint::Desktop => Self::SIDEBAR_WIDTH_DESKTOP,
            Breakpoint::Tablet => {
                let proportional = self.viewport_width * 0.35;
                proportional.clamp(Self::SIDEBAR_WIDTH_MIN, Self::SIDEBAR_WIDTH_TABLET)
            }
            Breakpoint::Mobile => self.viewport_width,
        }
    }

    pub fn header_height(&self) -> f32 {
        if self.is_mobile() {
            Self::HEADER_HEIGHT_MOBILE
        } else {
            Self::HEADER_HEIGHT
        }
    }

    pub fn chat_item_height(&self) -> f32 {
        match self.breakpoint {
            Breakpoint::Desktop => Self::CHAT_ITEM_HEIGHT_DESKTOP,
            Breakpoint::Tablet => Self::CHAT_ITEM_HEIGHT_TABLET,
            Breakpoint::Mobile => Self::CHAT_ITEM_HEIGHT_MOBILE,
        }
    }

    pub fn avatar_size(&self) -> f32 {
        if self.is_mobile() {
            Self::AVATAR_SIZE_MOBILE
        } else {
            Self::AVATAR_SIZE_LARGE
        }
    }

    pub fn input_area_height(&self) -> f32 {
        if self.is_mobile() {
            Self::INPUT_AREA_HEIGHT_MOBILE
        } else {
            Self::INPUT_AREA_HEIGHT
        }
    }

    pub fn max_bubble_width(&self) -> f32 {
        match self.breakpoint {
            Breakpoint::Desktop => Self::MAX_BUBBLE_WIDTH_DESKTOP,
            Breakpoint::Tablet => Self::MAX_BUBBLE_WIDTH_TABLET,
            Breakpoint::Mobile => {
                (self.viewport_width * Self::MAX_BUBBLE_WIDTH_MOBILE_RATIO).min(350.0)
            }
        }
    }

    pub fn max_media_size(&self) -> f32 {
        match self.breakpoint {
            Breakpoint::Desktop => Self::MAX_MEDIA_SIZE_DESKTOP,
            Breakpoint::Tablet => Self::MAX_MEDIA_SIZE_TABLET,
            Breakpoint::Mobile => {
                (self.viewport_width * Self::MAX_MEDIA_SIZE_MOBILE_RATIO).min(280.0)
            }
        }
    }

    pub fn chat_area_width(&self) -> f32 {
        match self.breakpoint {
            Breakpoint::Desktop | Breakpoint::Tablet => self.viewport_width - self.sidebar_width(),
            Breakpoint::Mobile => self.viewport_width,
        }
    }

    pub fn message_list_width(&self) -> f32 {
        self.chat_area_width() - 32.0 - 12.0
    }

    pub fn min_touch_target(&self) -> f32 {
        if self.is_mobile() { 48.0 } else { 36.0 }
    }

    pub fn icon_button_size(&self) -> f32 {
        if self.is_mobile() { 44.0 } else { 36.0 }
    }

    pub fn padding(&self) -> f32 {
        if self.is_mobile() { 12.0 } else { 16.0 }
    }

    pub fn padding_small(&self) -> f32 {
        if self.is_mobile() { 8.0 } else { 12.0 }
    }

    pub fn gap(&self) -> f32 {
        if self.is_mobile() { 8.0 } else { 12.0 }
    }
}
