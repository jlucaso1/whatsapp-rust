# WhatsApp UI

A native WhatsApp client built with [GPUI](https://github.com/zed-industries/zed/tree/main/crates/gpui) (the GPU-accelerated UI framework from Zed) that integrates with the `whatsapp-rust` library.

## Why GPUI?

- **GPU-accelerated rendering** via Vulkan/Metal/DX12 (using Blade graphics backend)
- **Reactive architecture** - UI only re-renders when state changes
- **Hybrid immediate/retained mode** - best of both worlds
- **Battle-tested** - powers the Zed code editor
- **Rich component library** via [gpui-component](https://longbridge.github.io/gpui-component/)

## Architecture

```
whatsapp-ui/
├── src/
│   ├── main.rs              # Entry point
│   ├── app.rs               # WhatsAppApp struct, event handling, render logic
│   ├── theme.rs             # Colors and layout constants
│   ├── client/              # WhatsApp client wrapper
│   │   ├── mod.rs
│   │   └── whatsapp.rs      # Async client logic
│   ├── state/               # Application state
│   │   ├── mod.rs
│   │   ├── app_state.rs     # AppState enum (Loading, Connected, etc.)
│   │   ├── chat.rs          # Chat, ChatMessage, MediaContent structs
│   │   ├── call.rs          # IncomingCall, ActiveCall structs
│   │   └── events.rs        # UiEvent enum for client->UI communication
│   ├── components/          # Reusable UI components
│   │   ├── mod.rs
│   │   ├── avatar.rs        # Avatar with gpui-component
│   │   ├── chat_header.rs   # Chat header bar
│   │   ├── chat_item.rs     # Single chat in list
│   │   ├── chat_list.rs     # Chat list sidebar with VirtualList
│   │   ├── input_area.rs    # Message input field
│   │   ├── message_bubble.rs # Message bubble with media support
│   │   └── message_list.rs  # Message list with VirtualList
│   └── views/               # Application views
│       ├── mod.rs
│       ├── loading.rs       # Loading/connecting spinner views
│       ├── pairing.rs       # QR code/pair code view
│       ├── error.rs         # Error view with retry button
│       └── chat.rs          # Main connected view
├── Cargo.toml
└── README.md
```

## Module Overview

### `theme.rs`
Contains WhatsApp dark theme colors and layout constants:
- `colors::*` - Background, text, accent colors
- `layout::*` - Dimensions for sidebar, headers, avatars, etc.

### `components/`
Reusable UI components built with GPUI and gpui-component:
- **Avatar** - User avatar with initials fallback (uses gpui-component)
- **ChatItem** - Single chat entry in the sidebar list
- **ChatList** - VirtualList-based scrollable chat sidebar
- **MessageBubble** - Message bubble with media (images, stickers, audio, docs)
- **MessageList** - VirtualList-based scrollable message area
- **ChatHeader** - Header bar showing chat name and avatar
- **InputArea** - Message input with send button

### `views/`
Application views for different states:
- **Loading/Connecting** - Spinner with status message
- **Pairing** - QR code display and pair code
- **Error** - Error message with retry button
- **Chat** - Main connected view with sidebar and chat area

### `app.rs`
Main application logic:
- `WhatsAppApp` struct with all state
- Event handling from WhatsApp client
- Render dispatch based on AppState

## GPUI Concepts

### Render Trait

Components implement the `Render` trait:

```rust
impl Render for WhatsAppApp {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        // Process events and dispatch to appropriate view
        match &self.app_state {
            AppState::Loading => render_loading_view(),
            AppState::Connected => render_connected_view(self, window, cx),
            // ...
        }
    }
}
```

### Reactive Updates

GPUI uses `cx.notify()` to trigger re-renders when state changes:

```rust
fn handle_event(&mut self, event: UiEvent, cx: &mut Context<Self>) {
    match event {
        UiEvent::Connected => {
            self.app_state = AppState::Connected;
            cx.notify(); // Trigger re-render
        }
        // ...
    }
}
```

### VirtualList for Performance

Large lists use VirtualList for efficient rendering:

```rust
v_virtual_list(
    entity,
    "message-list",
    item_sizes,
    |_view, visible_range, _scroll_handle, _cx| {
        visible_range
            .map(|ix| render_message_bubble(messages[ix].clone()))
            .collect()
    },
)
.track_scroll(&scroll_handle)
```

### Styling (Tailwind-like API)

```rust
div()
    .flex()
    .flex_col()
    .gap_4()
    .p_4()
    .bg(rgb(colors::BG_SECONDARY))
    .rounded(px(layout::RADIUS_MEDIUM))
    .text_color(rgb(colors::TEXT_PRIMARY))
```

## Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                         WhatsAppApp                             │
│                                                                 │
│  ┌─────────────────┐         ┌─────────────────────────────┐   │
│  │   WhatsAppClient│────────►│  mpsc::UnboundedReceiver    │   │
│  │  (background    │ UiEvent │  (polled via animation      │   │
│  │   thread)       │         │   frame callback)           │   │
│  └─────────────────┘         └──────────────┬──────────────┘   │
│                                             │                   │
│                                             ▼                   │
│                              ┌──────────────────────────────┐  │
│                              │  handle_event()              │  │
│                              │  - Updates app_state         │  │
│                              │  - Calls cx.notify()         │  │
│                              └──────────────┬───────────────┘  │
│                                             │                   │
│                                             ▼                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                     render()                             │   │
│  │                                                          │   │
│  │  match app_state:                                        │   │
│  │    Loading    -> render_loading_view()                   │   │
│  │    Connecting -> render_connecting_view()                │   │
│  │    Pairing    -> render_pairing_view()                   │   │
│  │    Connected  -> render_connected_view()                 │   │
│  │    Error      -> render_error_view()                     │   │
│  │                                                          │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## gpui-component

We use the [gpui-component](https://longbridge.github.io/gpui-component/) library for pre-built UI components:

- **Avatar** - User profile with fallback initials
- **Button** - Primary, secondary, danger variants
- **Input** - Text input with placeholder
- **Spinner** - Loading indicator
- **Scrollbar** - Custom scrollbar for lists
- **VirtualList** - Efficient scrollable lists
- And 50+ more components

## Running

```bash
# Development build
cargo run -p whatsapp-ui

# Release build (optimized)
cargo run --release -p whatsapp-ui
```

## Dependencies

- **gpui**: GPU-accelerated UI framework (from Zed)
- **gpui-component**: Pre-built UI components
- **tokio**: Async runtime
- **whatsapp-rust**: WhatsApp Web client library
- **chrono**: Date/time handling
- **log/env_logger**: Logging
- **image**: Image decoding (PNG, JPEG, WebP)

## Features Status

- [x] Basic app structure with GPUI
- [x] Loading/Connecting views with Spinner
- [x] Pairing view (QR code placeholder)
- [x] Connected view with chat layout
- [x] Error view with retry button
- [x] Event handling from WhatsApp client
- [x] Chat list with VirtualList
- [x] Message bubbles with media support
- [x] Image/sticker display
- [x] Input field for messages
- [x] Modular component architecture
- [ ] QR code rendering
- [ ] Call UI components

## Future Improvements

- [ ] Contact name resolution from address book
- [ ] Message sending status (pending, sent, delivered, read)
- [ ] Group chat features (participants, admin actions)
- [ ] Settings/preferences screen
- [ ] Notification system
- [ ] Voice/video call integration with WebRTC
- [ ] Theme customization
