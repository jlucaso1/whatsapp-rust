fn main() -> std::io::Result<()> {
    let mut config = prost_build::Config::new();
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    // The paths are now relative to the new crate's root
    config.compile_protos(&["src/whatsapp.proto"], &["src/"])?;
    Ok(())
}
