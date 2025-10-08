fn main() -> std::io::Result<()> {
    if std::env::var("GENERATE_PROTO").is_err() {
        println!("cargo:rerun-if-changed=build.rs");
        return Ok(());
    }
    println!("cargo:rerun-if-changed=src/whatsapp.proto");
    println!("cargo:warning=GENERATE_PROTO is set, regenerating proto definitions...");

    let mut config = prost_build::Config::new();
    let serde_derive = "#[derive(serde::Serialize, serde::Deserialize)]";

    config.message_attribute(".whatsapp.ADVSignedDeviceIdentity", serde_derive);

    config.message_attribute(".whatsapp.RecordStructure", serde_derive);
    config.message_attribute(".whatsapp.SessionStructure", serde_derive);

    config.message_attribute(".whatsapp.PreKeyRecordStructure", serde_derive);
    config.message_attribute(".whatsapp.SignedPreKeyRecordStructure", serde_derive);

    config.message_attribute(".whatsapp.SenderKeyRecordStructure", serde_derive);
    config.message_attribute(".whatsapp.SenderKeyStateStructure", serde_derive);

    config.out_dir("src/");
    config.compile_protos(&["src/whatsapp.proto"], &["src/"])?;

    Ok(())
}
