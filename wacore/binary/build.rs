use phf_codegen::Map;
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

fn main() {
    println!("cargo:rerun-if-changed=src/tokens.json");
    println!("cargo:rerun-if-changed=build.rs");

    let path = Path::new(&env::var("OUT_DIR").unwrap()).join("token_maps.rs");
    let mut file = BufWriter::new(File::create(&path).unwrap());

    let tokens_json = fs::read_to_string("src/tokens.json").unwrap();
    let tokens: Tokens = serde_json::from_str(&tokens_json).unwrap();

    // Unified token map: single lookup for both single-byte and double-byte tokens.
    // TokenKind::Single(u8) for single-byte, TokenKind::Double(u8, u8) for double-byte.
    let mut unified_map = Map::new();
    let mut values = Vec::new();
    let mut seen: HashMap<&str, &str> = HashMap::new();

    for (i, token) in tokens.single_byte.iter().enumerate() {
        if !token.is_empty() {
            values.push((token.clone(), format!("TokenKind::Single({})", i)));
        }
    }

    for (dict_idx, dict) in tokens.double_byte.iter().enumerate() {
        for (token_idx, token) in dict.iter().enumerate() {
            if !token.is_empty() {
                values.push((
                    token.clone(),
                    format!("TokenKind::Double({}, {})", dict_idx, token_idx),
                ));
            }
        }
    }

    for (token, value) in &values {
        if let Some(existing) = seen.get(token.as_str()) {
            panic!(
                "duplicate token {:?}: already mapped as {}, conflicting with {}",
                token, existing, value
            );
        }
        seen.insert(token.as_str(), value.as_str());
        unified_map.entry(token.as_str(), value.as_str());
    }

    writeln!(
        &mut file,
        "static TOKEN_MAP: phf::Map<&'static str, TokenKind> = \n{};",
        unified_map.build()
    )
    .unwrap();

    // Decode arrays: index → string (inverse of TOKEN_MAP)
    writeln!(&mut file, "\nstatic SINGLE_BYTE_TOKENS: &[&str] = &[").unwrap();
    for token in &tokens.single_byte {
        writeln!(&mut file, "    {:?},", token).unwrap();
    }
    writeln!(&mut file, "];").unwrap();

    writeln!(&mut file, "\nstatic DOUBLE_BYTE_TOKENS: &[&[&str]] = &[").unwrap();
    for dict in &tokens.double_byte {
        writeln!(&mut file, "    &[").unwrap();
        for token in dict {
            writeln!(&mut file, "        {:?},", token).unwrap();
        }
        writeln!(&mut file, "    ],").unwrap();
    }
    writeln!(&mut file, "];").unwrap();
}
