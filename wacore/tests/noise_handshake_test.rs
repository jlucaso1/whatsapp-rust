use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use hkdf::Hkdf;
use sha2::Sha256;
use wacore::handshake::NoiseHandshake;
use wacore::libsignal::crypto::CryptographicHash;
use wacore::libsignal::protocol::{PrivateKey, PublicKey};
use wacore::noise::generate_iv;
use wacore_binary::consts::{NOISE_START_PATTERN, WA_CONN_HEADER};

fn hex_to_bytes<const N: usize>(hex_str: &str) -> [u8; N] {
    hex::decode(hex_str)
        .expect("hex string should be valid")
        .try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("Expected length {}, but got {}", N, v.len()))
}

#[test]
fn test_server_static_key_decryption_with_go_values() {
    let client_eph_priv =
        hex::decode("58a49f1c633f3d5161f6b7854c13d4b28ba4b6b5fe91644a5fc3c09fd623e07d")
            .expect("test hex data should be valid");
    let server_eph_pub =
        hex::decode("9d9b8241572937f6672ce07221c143bc1cb1266334333f33797a592669523733")
            .expect("test hex data should be valid");
    let salt_before_mix =
        hex::decode("4e6f6973655f58585f32353531395f41455347434d5f53484132353600000000")
            .expect("test hex data should be valid");
    let go_salt_after_mix =
        hex::decode("cf20e4a2d076541a3f45609407f6501d9f20d55f40b06ff32af4573c44ab1595")
            .expect("test hex data should be valid");
    let aad_for_decrypt =
        hex::decode("42e2950db11903f6fd490bedd1cc630feb40b1d01ac350655a98273284498a1d")
            .expect("test hex data should be valid");
    let ciphertext = hex::decode("6de6577bb273d20bb64ee96ffc99fabd1390853791c26fad729806b5b7ddedc44d689b48e05068e2823b44dd533fff8d").expect("test hex data should be valid");
    let expected_plaintext =
        hex::decode("5854d333d8e13975abd6597bbaddd49d6935ced25c93a44bd3ade508f2bec330")
            .expect("test hex data should be valid");

    let our_private_key =
        PrivateKey::deserialize(&client_eph_priv).expect("test private key should deserialize");
    let their_public_key = PublicKey::from_djb_public_key_bytes(&server_eph_pub)
        .expect("test public key should deserialize");

    let rust_shared_secret = our_private_key
        .calculate_agreement(&their_public_key)
        .expect("key agreement should succeed");

    let (rust_salt_after_mix, rust_key_for_decrypt) = {
        let okm = {
            let hk = Hkdf::<Sha256>::new(Some(&salt_before_mix), &rust_shared_secret);
            let mut result = vec![0u8; 64];
            hk.expand(&[], &mut result)
                .expect("HKDF expansion should succeed");
            result
        };

        let mut salt = [0u8; 32];
        let mut key = [0u8; 32];

        salt.copy_from_slice(&okm[..32]);
        key.copy_from_slice(&okm[32..]);
        (salt, key)
    };

    assert_eq!(
        hex::encode(rust_salt_after_mix),
        hex::encode(go_salt_after_mix),
        "Derived SALT does not match Go's value!"
    );

    let cipher =
        Aes256Gcm::new_from_slice(&rust_key_for_decrypt).expect("Failed to prepare GCM cipher");

    let iv = generate_iv(0);
    let payload = Payload {
        msg: &ciphertext,
        aad: &aad_for_decrypt,
    };

    let rust_plaintext = cipher.decrypt(iv.as_ref().into(), payload)
        .expect("AEAD DECRYPTION FAILED! The test inputs are correct, so the GCM primitive or its inputs are flawed.");

    assert_eq!(
        hex::encode(rust_plaintext),
        hex::encode(expected_plaintext),
        "Final decrypted plaintext does not match Go's result!"
    );

    println!("✅ Test passed! Cryptographic primitives are behaving as expected.");
}

#[test]
fn test_live_decryption_with_go_values() {
    use aes_gcm::aead::{Aead, Payload};
    use hex;

    let go_derived_key_hex = "0e34efece6dc4516c05c53bb7e0c2128bc66c053da4e0b18afb0afe8e648c05d";
    let go_aad_hex = "78b3c79d1c15cf84ec402678ac0478106a6f201a77e4d2364de1e096d65c7bfe";
    let go_ciphertext_hex = "920d8096b1c0e4376e0667c877d746fb2697c72b940beb73e89f87cc79e43aae6a23ed5c5ec7a4e37f04a9c4a9a25f02";
    let go_expected_plaintext_hex =
        "5854d333d8e13975abd6597bbaddd49d6935ced25c93a44bd3ade508f2bec330";

    let go_derived_key = hex::decode(go_derived_key_hex).expect("test hex data should be valid");
    let aad = hex::decode(go_aad_hex).expect("test hex data should be valid");
    let ciphertext = hex::decode(go_ciphertext_hex).expect("test hex data should be valid");
    let expected_plaintext =
        hex::decode(go_expected_plaintext_hex).expect("test hex data should be valid");

    let cipher = Aes256Gcm::new_from_slice(&go_derived_key).expect("Failed to prepare GCM cipher");

    let iv = generate_iv(0);

    let payload = Payload {
        msg: &ciphertext,
        aad: &aad,
    };

    let rust_plaintext = cipher
        .decrypt(iv.as_ref().into(), payload)
        .expect("AEAD DECRYPTION FAILED! The GCM primitive or its inputs are flawed.");

    assert_eq!(
        hex::encode(&rust_plaintext),
        hex::encode(&expected_plaintext),
        "Final decrypted plaintext does not match Go's result!"
    );

    println!("✅ Test `test_live_decryption_with_go_values` passed! The GCM primitive is correct.");
}

#[test]
fn test_full_handshake_flow_with_go_data() {
    let client_eph_priv =
        hex_to_bytes::<32>("b8de0b5ebad3e7879fa659c0d27baa6c3e3f32a10f7c4cb2613cb4182fe83047");
    let client_eph_pub =
        hex_to_bytes::<32>("8537e1daadfb8e9ff8491896f5733008bad4967c2ba97670f69cf3053762ea4d");
    let wa_header = &WA_CONN_HEADER;

    let hash_after_prologue =
        hex_to_bytes::<32>("ffff0c9267310966f1311170c04b38c79504285bf5edf763e5c946492a50a755");
    let hash_after_auth_client_eph =
        hex_to_bytes::<32>("86790a969b7100866dfbf74fcfe5a175f8adff7f8c5139f74cd2f14a8fa5f11f");

    let server_eph_pub =
        hex_to_bytes::<32>("27692cf5d6a08e51f2d601f2e475378456bda16f96255c5121d081d0aa4a815d");
    let hash_after_auth_server_eph =
        hex_to_bytes::<32>("9fd7bf2736e1e5b48b2759fd5806225ccb6822d557579d725459795cdd0885d3");

    let salt_after_mix_1 =
        hex_to_bytes::<32>("a505e995a2068e7103a582be6f6ba9d6b447a80db4e679209b2f7cc6da633709");

    let aad_for_decrypt_1 =
        hex_to_bytes::<32>("9fd7bf2736e1e5b48b2759fd5806225ccb6822d557579d725459795cdd0885d3");
    let ciphertext_for_decrypt_1 = hex::decode("0addd1ce96c55699824fc20ef2a73928dd8168bc29ef863bdea6dc69002b00054add28f7711e3a7dff984d3f31badaa2").expect("test hex data should be valid");
    let plaintext_from_decrypt_1 =
        hex_to_bytes::<32>("5854d333d8e13975abd6597bbaddd49d6935ced25c93a44bd3ade508f2bec330");
    let hash_after_decrypt_1 =
        hex_to_bytes::<32>("8f29e8901b6ffb3cb393795c023d6d219ceb447dbbbae075533010907cbfbc6c");

    let salt_after_mix_2 =
        hex_to_bytes::<32>("5092572187a71abe8044010b9c8419633272b45b2babf4ca316966edc3eb9bde");

    let aad_for_decrypt_2 =
        hex_to_bytes::<32>("8f29e8901b6ffb3cb393795c023d6d219ceb447dbbbae075533010907cbfbc6c");
    let ciphertext_for_decrypt_2 = hex::decode("c4f948e737857d6bd675fa0a84f38ed784685b784402da53f972388a8aa3398f01be799862907d43cce7a49858023ec66dc909d1eac245f842661360804acf4975801ca0a156f876ba6004cc2f1241f761f753c516cef59fb3c6b95d39ad6d3540caa40b361bfbb7189eaa2d331e086870f2bd846bc6653cf2887387ba25268c9923dec5ecdc5ee37507680ba6906550f9991f6a60b2dc74803c6df8d6df352f206c376b0bb3d7d17dca91e3999f73d6dc6469e59281bc18c22fd1e7d85467b3f17fafc141a62c6fd92d364310d5b32493c9f2c77817aa4d901aef2538858b157d46ea247371a9c2f577171796fa7be059d975dddee115d5aa967602b02a93be36").expect("test hex data should be valid");
    let plaintext_from_decrypt_2 = hex::decode("0a770a3308c90210031a205854d333d8e13975abd6597bbaddd49d6935ced25c93a44bd3ade508f2bec33020d08f87bf0628d0c99fc406124019cbee71b63bb8048af269f3aa7c13c62a1fd89ac4ef2509d1d78d68267f40393b49a9cc38db05e35a6c5bf3ba6172a4c5325f25f363338cf8f3535a4cd9520512760a32080310001a201c51a9ac303994c6c8d0b92ea1878a533476599cc599fbea35997d9aa90cce62208091aebe0628ffdeb7dc061240270f294648539fed4870e25054dd4e95983aba29189c2ba6c8eeda7055555f753740f5ec192ab64c26c26d6ade6d20b9f774aee37120a6b20395f53c66058507").expect("test hex data should be valid");
    let hash_after_decrypt_2 =
        hex_to_bytes::<32>("4a82b448599eb44f85bacedaff0a81820999a87be156b08989c2857b8651d4d2");

    println!("Step 1: Prologue");
    let mut nh = NoiseHandshake::new(NOISE_START_PATTERN, wa_header)
        .expect("noise handshake should initialize");
    assert_eq!(*nh.hash(), hash_after_prologue, "Mismatch after prologue");

    println!("Step 2: Auth Client Ephemeral");
    nh.authenticate(&client_eph_pub);
    assert_eq!(
        *nh.hash(),
        hash_after_auth_client_eph,
        "Mismatch after auth client ephemeral"
    );

    println!("Step 3: Auth Server Ephemeral");
    nh.authenticate(&server_eph_pub);
    assert_eq!(
        *nh.hash(),
        hash_after_auth_server_eph,
        "Mismatch after auth server ephemeral"
    );

    println!("Step 4: First MixKey");
    nh.mix_shared_secret(&client_eph_priv, &server_eph_pub)
        .expect("first mix should succeed");
    assert_eq!(*nh.salt(), salt_after_mix_1, "Mismatch on SALT after mix 1");
    assert_eq!(
        *nh.hash(),
        hash_after_auth_server_eph,
        "Hash changed during mix 1, it should not have"
    );

    println!("Step 5: First Decrypt (Server Static Key)");
    assert_eq!(
        *nh.hash(),
        aad_for_decrypt_1,
        "AAD for decrypt 1 does not match current hash state"
    );

    let decrypted_static_bytes = nh
        .decrypt(&ciphertext_for_decrypt_1)
        .expect("first decrypt should succeed");
    assert_eq!(
        decrypted_static_bytes,
        plaintext_from_decrypt_1.to_vec(),
        "Plaintext from decrypt 1 mismatch"
    );
    assert_eq!(
        *nh.hash(),
        hash_after_decrypt_1,
        "Mismatch on HASH after decrypt 1"
    );

    println!("Step 6: Second MixKey");
    let decrypted_static_arr: [u8; 32] = decrypted_static_bytes
        .try_into()
        .expect("decrypted static bytes should be 32 bytes");
    nh.mix_shared_secret(&client_eph_priv, &decrypted_static_arr)
        .expect("second mix should succeed");
    assert_eq!(*nh.salt(), salt_after_mix_2, "Mismatch on SALT after mix 2");
    assert_eq!(
        *nh.hash(),
        hash_after_decrypt_1,
        "Hash changed during mix 2, it should not have"
    );

    println!("Step 7: Second Decrypt (Certificate)");
    assert_eq!(
        *nh.hash(),
        aad_for_decrypt_2,
        "AAD for decrypt 2 does not match current hash state"
    );

    let decrypted_cert_bytes = nh
        .decrypt(&ciphertext_for_decrypt_2)
        .expect("second decrypt should succeed");
    assert_eq!(
        decrypted_cert_bytes, plaintext_from_decrypt_2,
        "Plaintext from decrypt 2 mismatch"
    );
    assert_eq!(
        *nh.hash(),
        hash_after_decrypt_2,
        "Mismatch on HASH after decrypt 2"
    );

    println!("✅ All handshake crypto steps match Go implementation!");
}

#[test]
fn test_initial_pattern_hash() {
    let pattern = "Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00";
    let expected_hash =
        hex::decode("5df72b67b965add1168f0a6c756df21c204f7e64fc682be6a3ab4b682c8db64b")
            .expect("test hex data should be valid");

    let mut hasher = CryptographicHash::new("SHA-256").expect("test hex data should be valid");
    hasher.update(pattern.as_bytes());
    let actual_hash = hasher.finalize();

    assert_eq!(actual_hash.as_slice(), expected_hash.as_slice());
}
