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

    // Configure prost to output the file to the `src/` directory,
    // so it can be version-controlled.
    config.out_dir("src/");

    config.compile_protos(&["src/whatsapp.proto"], &["src/"])?;
    Ok(())
}
