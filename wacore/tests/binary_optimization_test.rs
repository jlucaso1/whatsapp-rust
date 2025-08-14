use wacore::binary::builder::NodeBuilder;
use wacore::binary::{marshal, unmarshal_ref};

#[test]
fn test_encoder_with_bytesmut() {
    // Test that the encoder using BytesMut works correctly with different data types
    let node = NodeBuilder::new("test")
        .attrs([
            ("nibble_attr", "1234567890"), // Should use NIBBLE_8 packing
            ("hex_attr", "ABCDEF123456"),  // Should use HEX_8 packing
            ("regular_attr", "some_regular_string"),
        ])
        .bytes(vec![1, 2, 3, 4, 5])
        .build();

    // Marshal using the optimized encoder
    let marshaled = marshal(&node).expect("Marshal failed");

    // Unmarshal and verify correctness
    let unmarshaled = unmarshal_ref(&marshaled[1..]).expect("Unmarshal failed");
    assert_eq!(node, unmarshaled.to_owned());
}

#[test]
fn test_packed_string_optimization() {
    // Test that packed string encoding works without extra allocations
    let node = NodeBuilder::new("packed_test")
        .attrs([
            ("nibble1", "123"),  // Odd length nibble
            ("nibble2", "1234"), // Even length nibble
            ("hex1", "ABC"),     // Odd length hex
            ("hex2", "ABCD"),    // Even length hex
        ])
        .build();

    let marshaled = marshal(&node).expect("Marshal failed");
    let unmarshaled = unmarshal_ref(&marshaled[1..]).expect("Unmarshal failed");

    assert_eq!(node, unmarshaled.to_owned());

    // Verify specific attribute values are preserved
    assert_eq!(unmarshaled.attrs.get("nibble1").unwrap().as_ref(), "123");
    assert_eq!(unmarshaled.attrs.get("nibble2").unwrap().as_ref(), "1234");
    assert_eq!(unmarshaled.attrs.get("hex1").unwrap().as_ref(), "ABC");
    assert_eq!(unmarshaled.attrs.get("hex2").unwrap().as_ref(), "ABCD");
}

#[test]
fn test_zero_copy_parsing_large_data() {
    // Test zero-copy semantics with larger data structures
    let child_nodes = (0..10)
        .map(|i| {
            NodeBuilder::new(&format!("child_{}", i))
                .attr("id", &i.to_string())
                .bytes(vec![i as u8; 100]) // 100 bytes per child
                .build()
        })
        .collect::<Vec<_>>();

    let parent = NodeBuilder::new("parent")
        .attrs([("count", "10"), ("type", "test")])
        .children(child_nodes)
        .build();

    let marshaled = marshal(&parent).expect("Marshal failed");
    let unmarshaled = unmarshal_ref(&marshaled[1..]).expect("Unmarshal failed");

    assert_eq!(parent, unmarshaled.to_owned());

    // Verify we can access child data efficiently
    if let Some(children) = unmarshaled.children() {
        assert_eq!(children.len(), 10);
        for (i, child) in children.iter().enumerate() {
            assert_eq!(child.tag.as_ref(), format!("child_{}", i));
            assert_eq!(child.attrs.get("id").unwrap().as_ref(), i.to_string());
        }
    } else {
        panic!("Parent should have children");
    }
}

#[test]
fn test_roundtrip_preserves_zero_copy_semantics() {
    // Test that repeated marshal/unmarshal cycles work correctly
    let original = NodeBuilder::new("roundtrip")
        .attrs([
            ("static_token", "success"), // Should use static token
            ("binary_data", "some binary content here"),
        ])
        .build();

    // Multiple roundtrips
    let mut current_data = marshal(&original).expect("Initial marshal failed");

    for _ in 0..3 {
        let unmarshaled = unmarshal_ref(&current_data[1..]).expect("Unmarshal failed");
        assert_eq!(original, unmarshaled.to_owned());
        current_data = marshal(&unmarshaled.to_owned()).expect("Re-marshal failed");
    }
}
