//! # Updating the proto
//!
//! 1. Edit `src/whatsapp.proto`.
//! 2. Optional: format with `buf format src/whatsapp.proto -w`.
//! 3. Regenerate the descriptor: `scripts/regenerate-proto-desc.sh`
//!    (wraps `protoc --descriptor_set_out=src/whatsapp.desc …`).
//! 4. `cargo build` — this script consumes `whatsapp.desc` and writes
//!    `whatsapp.rs` to `OUT_DIR`. Consumers never need `protoc` installed;
//!    only editors of the proto do.

fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-changed=src/whatsapp.desc");
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR must be set by cargo");
    let out_path = std::path::PathBuf::from(&out_dir);

    buffa_build::Config::new()
        .descriptor_set("src/whatsapp.desc")
        .files(&["whatsapp.proto"])
        // Serialize always; Deserialize only for WASM bridge (halves serde codegen).
        .type_attribute(".", "#[derive(serde::Serialize)]")
        .type_attribute(
            ".",
            "#[cfg_attr(feature = \"serde-deserialize\", derive(serde::Deserialize))]",
        )
        // Default missing fields to match protobuf semantics (structs only).
        .message_attribute(
            ".",
            "#[cfg_attr(feature = \"serde-deserialize\", serde(default))]",
        )
        // Accept snake_case on deserialization for WASM bridge enum variants.
        .type_attribute(
            ".",
            "#[cfg_attr(feature = \"serde-snake-case\", serde(rename_all(deserialize = \"snake_case\")))]",
        )
        // O(1)-clone Bytes for hot-path crypto structures instead of Vec<u8>.
        .use_bytes_type_in(&[
            ".whatsapp.SessionStructure.Chain.ChainKey",
            ".whatsapp.SessionStructure.Chain.MessageKey",
            ".whatsapp.SenderKeyStateStructure.SenderChainKey",
            ".whatsapp.SenderKeyStateStructure.SenderMessageKey",
            ".whatsapp.SenderKeyStateStructure.SenderSigningKey",
        ])
        // Bytes fields lack serde support; skip them (internal crypto state).
        .field_attribute(
            ".whatsapp.SessionStructure.Chain.ChainKey.key",
            "#[serde(skip)]",
        )
        .field_attribute(
            ".whatsapp.SessionStructure.Chain.MessageKey.cipher_key",
            "#[serde(skip)]",
        )
        .field_attribute(
            ".whatsapp.SessionStructure.Chain.MessageKey.mac_key",
            "#[serde(skip)]",
        )
        .field_attribute(
            ".whatsapp.SessionStructure.Chain.MessageKey.iv",
            "#[serde(skip)]",
        )
        .field_attribute(
            ".whatsapp.SenderKeyStateStructure.SenderChainKey.seed",
            "#[serde(skip)]",
        )
        .field_attribute(
            ".whatsapp.SenderKeyStateStructure.SenderMessageKey.seed",
            "#[serde(skip)]",
        )
        .field_attribute(
            ".whatsapp.SenderKeyStateStructure.SenderSigningKey.public",
            "#[serde(skip)]",
        )
        .field_attribute(
            ".whatsapp.SenderKeyStateStructure.SenderSigningKey.private",
            "#[serde(skip)]",
        )
        // We control both encoder and decoder — no need to preserve
        // unknown fields. Disabling removes __buffa_unknown_fields from
        // every struct, eliminating allocation/drop overhead in nested
        // types like SessionStructure (chains × message keys).
        .preserve_unknown_fields(false)
        // Generate view types for zero-copy decoding.
        .generate_views(true)
        .out_dir(&out_path)
        .compile()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    // Add #[serde(skip)] to buffa internal fields on owned types only.
    // Neither `UnknownFields` nor `CachedSize` impl serde traits, and view
    // structs don't derive serde, so the replace only targets owned types.
    let generated = out_path.join("whatsapp.rs");
    let content = std::fs::read_to_string(&generated)?;
    let content = content
        .replace(
            "pub __buffa_unknown_fields: ::buffa::UnknownFields,",
            "#[serde(skip)]\n    pub __buffa_unknown_fields: ::buffa::UnknownFields,",
        )
        .replace(
            "pub __buffa_cached_size:",
            "#[serde(skip)]\n    pub __buffa_cached_size:",
        );
    std::fs::write(&generated, content)?;

    Ok(())
}
