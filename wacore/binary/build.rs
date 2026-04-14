use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;

#[derive(Deserialize)]
struct Tokens {
    single_byte: Vec<String>,
    double_byte: Vec<Vec<String>>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=src/tokens.json");
    println!("cargo:rerun-if-changed=build.rs");

    let path = Path::new(&env::var("OUT_DIR")?).join("token_maps.rs");
    let mut file = BufWriter::new(File::create(&path)?);

    let tokens_json = fs::read_to_string("src/tokens.json")?;
    let tokens: Tokens = serde_json::from_str(&tokens_json)?;

    let mut values: Vec<(String, String)> = Vec::new();
    let mut seen: HashMap<String, String> = HashMap::new();

    for (i, token) in tokens.single_byte.iter().enumerate() {
        if !token.is_empty() {
            let kind = format!("TokenKind::Single({})", i);
            if let Some(existing) = seen.get(token) {
                panic!("duplicate token {:?}: {} vs {}", token, existing, kind);
            }
            seen.insert(token.clone(), kind.clone());
            values.push((token.clone(), kind));
        }
    }

    for (dict_idx, dict) in tokens.double_byte.iter().enumerate() {
        for (token_idx, token) in dict.iter().enumerate() {
            if !token.is_empty() {
                let kind = format!("TokenKind::Double({}, {})", dict_idx, token_idx);
                if let Some(existing) = seen.get(token) {
                    panic!("duplicate token {:?}: {} vs {}", token, existing, kind);
                }
                seen.insert(token.clone(), kind.clone());
                values.push((token.clone(), kind));
            }
        }
    }

    // Generate hashify PTHash lookup (FNV-1a, compile-time perfect hash)
    writeln!(
        file,
        "fn hashify_lookup(key: &[u8]) -> Option<&'static TokenKind> {{"
    )?;
    writeln!(file, "    hashify::map! {{")?;
    writeln!(file, "        key,")?;
    writeln!(file, "        TokenKind,")?;
    for (token, kind) in &values {
        writeln!(file, "        {:?} => {},", token.as_bytes(), kind)?;
    }
    writeln!(file, "    }}")?;
    writeln!(file, "}}")?;

    // Decode arrays: index → string
    writeln!(file, "\nstatic SINGLE_BYTE_TOKENS: &[&str] = &[")?;
    for token in &tokens.single_byte {
        writeln!(file, "    {:?},", token)?;
    }
    writeln!(file, "];")?;

    writeln!(file, "\nstatic DOUBLE_BYTE_TOKENS: &[&[&str]] = &[")?;
    for dict in &tokens.double_byte {
        writeln!(file, "    &[")?;
        for token in dict {
            writeln!(file, "        {:?},", token)?;
        }
        writeln!(file, "    ],")?;
    }
    writeln!(file, "];")?;

    Ok(())
}
