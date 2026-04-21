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
        println!("cargo:rerun-if-changed=src/voip.proto");
        println!("cargo:warning=Regenerating proto definitions...");

        let mut config = prost_build::Config::new();

        // Serialize always; Deserialize only for WASM bridge (halves serde codegen).
        config.type_attribute(".", "#[derive(serde::Serialize)]");
        config.type_attribute(
            ".",
            "#[cfg_attr(feature = \"serde-deserialize\", derive(serde::Deserialize))]",
        );
        // Default missing fields to match protobuf semantics (structs only).
        config.message_attribute(
            ".",
            "#[cfg_attr(feature = \"serde-deserialize\", serde(default))]",
        );

        // Accept snake_case on deserialization for WASM bridge enum variants.
        config.type_attribute(
            ".",
            "#[cfg_attr(feature = \"serde-snake-case\", serde(rename_all(deserialize = \"snake_case\")))]",
        );

        // O(1)-clone Bytes for hot-path crypto structures instead of Vec<u8>.
        config.bytes([
            ".whatsapp.SessionStructure.Chain.ChainKey",
            ".whatsapp.SessionStructure.Chain.MessageKey",
            ".whatsapp.SenderKeyStateStructure.SenderChainKey",
            ".whatsapp.SenderKeyStateStructure.SenderMessageKey",
            ".whatsapp.SenderKeyStateStructure.SenderSigningKey",
        ]);

        // Bytes fields lack serde support; skip them (internal crypto state).
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

        // Output to src/ so generated code is version-controlled.
        config.out_dir("src/");

        config.compile_protos(&["src/whatsapp.proto", "src/voip.proto"], &["src/"])?;
        Ok(())
    }
}
