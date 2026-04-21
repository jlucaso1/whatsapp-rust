# Debugging Tools

## evcxr - Rust REPL

For interactive debugging and quick code exploration:

```bash
cargo binstall evcxr_repl -y
evcxr  # run from project root
```

### Using Project Crates

```rust
:dep wacore-binary = { path = "wacore/binary" }
:dep hex = "0.4"

use wacore_binary::jid::Jid;
use wacore_binary::marshal::{marshal, unmarshal_ref};
use wacore_binary::builder::NodeBuilder;
```

**Important**: evcxr processes each line independently. For multi-line code with local variables, wrap in a block:

```rust
{
    let jid: Jid = "100000000000001.1:75@lid".parse().unwrap();
    println!("User: {}, Device: {}, Is LID: {}", jid.user, jid.device, jid.is_lid());
}
```

### Common Tasks

**Decode binary protocol data:**
```rust
{
    let data = hex::decode("f80f4c1a...").unwrap();
    let node = unmarshal_ref(&data).unwrap();
    println!("Tag: {}", node.tag);
    for (k, v) in node.attrs.iter() { println!("  {}: {}", k, v); }
}
```

**Build and marshal nodes:**
```rust
{
    let node = NodeBuilder::new("message")
        .attr("type", "text")
        .attr("to", "15551234567@s.whatsapp.net")
        .build();
    let bytes = marshal(&node).unwrap();
    println!("Marshaled: {:02x?}", bytes);
}
```

## Nibble Encoding

WhatsApp binary protocol uses nibble encoding for numeric strings. Each byte contains two digits (0-9), with 0xF as terminator for odd-length strings:

```rust
// Decode: "100000000000001f" -> "100000000000001"
// Encode: "100000000000001" -> "100000000000001f"
```

See `wacore/binary/src/nibble.rs` for the implementation.
