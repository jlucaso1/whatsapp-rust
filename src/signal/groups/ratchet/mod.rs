pub mod sender_chain_key;
pub mod sender_message_key;

// Temporary stub to allow compilation
pub fn get_sender_key<'a>(
    _state: &'a mut crate::signal::state::sender_key_state::SenderKeyState,
    _iteration: u32,
) -> Result<crate::signal::groups::ratchet::sender_message_key::SenderMessageKey, &'static str> {
    Err("get_sender_key not implemented")
}
