// # Updating the Proto File
//
// When modifying `src/whatsapp.proto`, follow these steps:
//
// 1. Format the proto file (requires `buf` CLI: https://buf.build/docs/installation):
//    ```
//    buf format waproto/src/whatsapp.proto -w
//    ```
//
// 2. Regenerate the Rust code:
//    ```
//    cargo build -p waproto --features generate
//    ```
//
// 3. Fix any breaking changes in the codebase (e.g., `optional` -> `required` field changes)

fn main() -> std::io::Result<()> {
    #[cfg(not(feature = "generate"))]
    {
        println!("cargo:rerun-if-changed=build.rs");
        Ok(())
    }

    #[cfg(feature = "generate")]
    {
        println!("cargo:rerun-if-changed=src/whatsapp.proto");
        println!("cargo:warning=Regenerating proto definitions...");

        let mut config = prost_build::Config::new();

        // Only derive Serialize by default. Deserialize is gated behind the
        // "serde-deserialize" feature — only needed by WASM bridge for JS interop.
        // This eliminates ~50% of serde-generated code for non-WASM builds.
        config.type_attribute(".", "#[derive(serde::Serialize)]");
        config.type_attribute(
            ".",
            "#[cfg_attr(feature = \"serde-deserialize\", derive(serde::Deserialize))]",
        );
        // Make serde deserialization lenient — use defaults for missing fields.
        // This matches protobuf semantics (missing = default value) and avoids
        // "missing field" errors when deserializing partial JSON from JS.
        // Uses message_attribute (not type_attribute) so it only applies to structs, not enums.
        config.message_attribute(
            ".",
            "#[cfg_attr(feature = \"serde-deserialize\", serde(default))]",
        );

        // Accept snake_case during deserialization. Primarily affects enum/oneof variants
        // (prost generates PascalCase) so the bridge's to_snake_case_js works. No-op for
        // struct fields (already snake_case). Serialize output unchanged.
        config.type_attribute(
            ".",
            "#[cfg_attr(feature = \"serde-snake-case\", serde(rename_all(deserialize = \"snake_case\")))]",
        );

        // Use bytes::Bytes instead of Vec<u8> for frequently-serialized cryptographic structures.
        // This enables O(1) cloning (reference-counted) instead of O(n) copying.
        // See: https://docs.rs/prost-build/latest/prost_build/struct.Config.html#method.bytes
        config.bytes([
            // Session chain keys (called on every message encrypt/decrypt)
            ".whatsapp.SessionStructure.Chain.ChainKey",
            ".whatsapp.SessionStructure.Chain.MessageKey",
            // Sender key structures (group messaging hot path)
            ".whatsapp.SenderKeyStateStructure.SenderChainKey",
            ".whatsapp.SenderKeyStateStructure.SenderMessageKey",
            ".whatsapp.SenderKeyStateStructure.SenderSigningKey",
        ]);

        // bytes::Bytes doesn't impl Serialize (prost's bytes dep lacks the serde feature).
        // Skip serializing these fields — they're internal crypto state, not API-visible.
        config.field_attribute(
            ".whatsapp.SessionStructure.Chain.ChainKey.key",
            "#[serde(skip)]",
        );
        config.field_attribute(
            ".whatsapp.SessionStructure.Chain.MessageKey.cipherKey",
            "#[serde(skip)]",
        );
        config.field_attribute(
            ".whatsapp.SessionStructure.Chain.MessageKey.macKey",
            "#[serde(skip)]",
        );
        config.field_attribute(
            ".whatsapp.SessionStructure.Chain.MessageKey.iv",
            "#[serde(skip)]",
        );
        config.field_attribute(
            ".whatsapp.SenderKeyStateStructure.SenderChainKey.seed",
            "#[serde(skip)]",
        );
        config.field_attribute(
            ".whatsapp.SenderKeyStateStructure.SenderMessageKey.seed",
            "#[serde(skip)]",
        );
        config.field_attribute(
            ".whatsapp.SenderKeyStateStructure.SenderSigningKey.public",
            "#[serde(skip)]",
        );
        config.field_attribute(
            ".whatsapp.SenderKeyStateStructure.SenderSigningKey.private",
            "#[serde(skip)]",
        );

        // Configure prost to output the file to the `src/` directory,
        // so it can be version-controlled.
        config.out_dir("src/");

        config.compile_protos(&["src/whatsapp.proto"], &["src/"])?;
        Ok(())
    }
}
