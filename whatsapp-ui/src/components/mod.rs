//! Reusable UI components

mod avatar;
mod call_popup;
mod chat_header;
mod chat_item;
mod chat_list;
mod input_area_view;
mod message_bubble;
mod message_list;
mod outgoing_call_popup;

pub use avatar::Avatar;
pub use call_popup::{render_call_popup, render_call_popup_base};
pub use chat_header::render_chat_header;
pub use chat_item::render_chat_item;
pub use chat_list::render_chat_list;
pub use input_area_view::{InputAreaEvent, InputAreaView};
pub use message_bubble::render_message_bubble;
pub use message_list::render_message_list;
pub use outgoing_call_popup::render_outgoing_call_popup;
