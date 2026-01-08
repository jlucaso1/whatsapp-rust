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
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");

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

    // Skip serde for Bytes fields since bytes::Bytes doesn't implement Serialize/Deserialize
    // without the serde feature which prost doesn't expose. These nested types aren't JSON
    // serialized anyway - they're stored as protobuf blobs.
    // We use skip + default so serde doesn't try to deserialize these fields.
    config.field_attribute(
        ".whatsapp.SessionStructure.Chain.ChainKey.key",
        "#[serde(skip, default)]",
    );
    config.field_attribute(
        ".whatsapp.SessionStructure.Chain.MessageKey.cipherKey",
        "#[serde(skip, default)]",
    );
    config.field_attribute(
        ".whatsapp.SessionStructure.Chain.MessageKey.macKey",
        "#[serde(skip, default)]",
    );
    config.field_attribute(
        ".whatsapp.SessionStructure.Chain.MessageKey.iv",
        "#[serde(skip, default)]",
    );
    config.field_attribute(
        ".whatsapp.SenderKeyStateStructure.SenderChainKey.seed",
        "#[serde(skip, default)]",
    );
    config.field_attribute(
        ".whatsapp.SenderKeyStateStructure.SenderMessageKey.seed",
        "#[serde(skip, default)]",
    );
    config.field_attribute(
        ".whatsapp.SenderKeyStateStructure.SenderSigningKey.public",
        "#[serde(skip, default)]",
    );
    config.field_attribute(
        ".whatsapp.SenderKeyStateStructure.SenderSigningKey.private",
        "#[serde(skip, default)]",
    );

    // Configure prost to output the file to the `src/` directory,
    // so it can be version-controlled.
    config.out_dir("src/");

    config.compile_protos(&["src/whatsapp.proto"], &["src/"])?;
    Ok(())
}
