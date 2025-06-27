fn main() -> std::io::Result<()> {
    prost_build::compile_protos(&["src/proto/whatsapp.proto"], &["src/"])?;
    Ok(())
}
