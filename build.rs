fn main() -> std::io::Result<()> {
    let mut config = prost_build::Config::new();
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    config.compile_protos(&["src/proto/whatsapp.proto"], &["src/"])?;
    Ok(())
}
