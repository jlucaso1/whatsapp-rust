#[cfg(test)]
mod tests {
    use hex;
    
    #[test]
    fn test_crypto_compatibility() {
        // Test data - some random key, iv, and plaintext
        let key = hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").unwrap();
        let iv = hex::decode("0123456789abcdef0123456789abcdef").unwrap();
        let plaintext = b"Hello, World! This is a test message for crypto compatibility.";

        // Encrypt with old implementation
        let ciphertext_old = wacore::crypto::cbc::encrypt(&key, &iv, plaintext).unwrap();
        
        // Decrypt with libsignal implementation
        let decrypted_libsignal = wacore::libsignal::crypto::aes_256_cbc_decrypt(&ciphertext_old, &key, &iv).unwrap();
        
        assert_eq!(plaintext, &decrypted_libsignal[..]);
        
        // Also test the reverse
        let ciphertext_libsignal = wacore::libsignal::crypto::aes_256_cbc_encrypt(plaintext, &key, &iv).unwrap();
        let decrypted_old = wacore::crypto::cbc::decrypt(&key, &iv, &ciphertext_libsignal).unwrap();
        
        assert_eq!(plaintext, &decrypted_old[..]);
        
        println!("✅ Crypto compatibility test passed!");
    }
}