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
//    GENERATE_PROTO=1 cargo build -p waproto
//    ```
//
// 3. Fix any breaking changes in the codebase (e.g., `optional` -> `required` field changes)

fn main() -> std::io::Result<()> {
    // By default, we expect the `whatsapp.rs` file to be pre-generated.
    // This build script will only regenerate it if the `GENERATE_PROTO`
    // environment variable is set. This is intended for developers who modify
    // the `.proto` file.
    if std::env::var("GENERATE_PROTO").is_err() {
        println!("cargo:rerun-if-changed=build.rs");
        // For a normal build, do nothing.
        return Ok(());
    }

    // This part runs only when `GENERATE_PROTO=1` is in the environment.
    println!("cargo:rerun-if-changed=src/whatsapp.proto");
    println!("cargo:warning=GENERATE_PROTO is set, regenerating proto definitions...");

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
