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

        buffa_build::Config::new()
            .files(&["src/whatsapp.proto"])
            .includes(&["src/"])
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
            // Generate view types for zero-copy decoding.
            .generate_views(true)
            // Output to src/ so generated code is version-controlled.
            .out_dir("src/")
            .compile()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        // Post-process: fix buffa codegen bug where as_option_mut() is called on
        // MessageFieldView (views are immutable). Replace with always-set semantics.
        // Filed upstream: https://github.com/anthropics/buffa/issues/36
        // Post-process: add #[serde(skip)] to buffa internal fields on owned types only.
        // buffa adds __buffa_unknown_fields and __buffa_cached_size to every struct,
        // which don't implement serde traits. View types don't derive serde so we
        // must only annotate owned-type fields (UnknownFields, not UnknownFieldsView).
        let path = std::path::Path::new("src/whatsapp.rs");
        let content = std::fs::read_to_string(path)?;
        let content = content
            .replace(
                "pub __buffa_unknown_fields: ::buffa::UnknownFields,",
                "#[serde(skip)]\n    pub __buffa_unknown_fields: ::buffa::UnknownFields,",
            )
            .replace(
                "pub __buffa_cached_size:",
                "#[serde(skip)]\n    pub __buffa_cached_size:",
            );
        std::fs::write(path, content)?;

        Ok(())
    }
}
