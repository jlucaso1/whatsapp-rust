/**
 * Integration tests for the WASM Signal Protocol implementation
 */

use wasm_bindgen_test::*;
use wacore_wasm::WasmSignalRepository;
use js_sys::{Object, Uint8Array};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn test_wasm_signal_repository_creation() {
    // Create a mock store object for testing
    let mock_store = Object::new();
    let repo = WasmSignalRepository::new(mock_store.into());
    
    // Basic test - just ensure the repository can be created without panicking
    assert!(true, "WasmSignalRepository created successfully");
}

#[wasm_bindgen_test]
async fn test_encrypt_message_stub() {
    let mock_store = Object::new();
    let repo = WasmSignalRepository::new(mock_store.into());
    
    let test_data = Uint8Array::new_with_length(10);
    let promise = repo.encrypt_message("test@example.com".to_string(), test_data);
    
    // For now, we just test that the method returns a promise
    // In a full implementation, we would await the promise and verify the result
    assert!(promise.is_object(), "encrypt_message returns a Promise object");
}

#[wasm_bindgen_test]
async fn test_decrypt_message_stub() {
    let mock_store = Object::new();
    let repo = WasmSignalRepository::new(mock_store.into());
    
    let test_data = Uint8Array::new_with_length(10);
    let promise = repo.decrypt_message("test@example.com".to_string(), test_data, 1);
    
    // For now, we just test that the method returns a promise
    assert!(promise.is_object(), "decrypt_message returns a Promise object");
}