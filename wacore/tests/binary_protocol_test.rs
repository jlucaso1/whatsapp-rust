use std::collections::HashMap;
use wacore::binary::{
    marshal,
    node::{Node, NodeContent},
    unmarshal_ref,
};

#[test]
fn test_simple_node_roundtrip_with_ref() {
    let original_node = Node {
        tag: "test".to_string(),
        attrs: HashMap::new(),
        content: None,
    };

    // marshal() adds a leading flag byte (0 for uncompressed)
    let marshaled_with_flag = marshal(&original_node).expect("Marshal failed");

    // unmarshal_ref() expects the data *without* the flag byte.
    // It returns a borrowed `NodeRef`.
    let unmarshaled_ref = unmarshal_ref(&marshaled_with_flag[1..]).expect("unmarshal_ref failed");

    // Convert the borrowed `NodeRef` back to an owned `Node` for comparison.
    assert_eq!(original_node, unmarshaled_ref.to_owned());
}

#[test]
fn test_node_with_attributes_and_content_with_ref() {
    let original_node = Node {
        tag: "iq".to_string(),
        attrs: [
            ("key1".to_string(), "value1".to_string()),
            ("type".to_string(), "get".to_string()),
        ]
        .into(),
        content: Some(NodeContent::Bytes(b"hello world".to_vec())),
    };

    let marshaled_with_flag = marshal(&original_node).expect("Marshal failed");
    let unmarshaled_ref = unmarshal_ref(&marshaled_with_flag[1..]).expect("unmarshal_ref failed");

    assert_eq!(original_node, unmarshaled_ref.to_owned());
}

#[test]
fn test_node_with_children_with_ref() {
    let child1 = Node {
        tag: "child1".to_string(),
        attrs: HashMap::new(),
        content: None,
    };
    let child2 = Node {
        tag: "child2".to_string(),
        attrs: [("id".to_string(), "123".to_string())].into(),
        content: None,
    };

    let parent_node = Node {
        tag: "parent".to_string(),
        attrs: HashMap::new(),
        content: Some(NodeContent::Nodes(vec![child1, child2])),
    };

    let marshaled_with_flag = marshal(&parent_node).expect("Marshal failed");
    let unmarshaled_ref = unmarshal_ref(&marshaled_with_flag[1..]).expect("unmarshal_ref failed");

    assert_eq!(parent_node, unmarshaled_ref.to_owned());
}

#[test]
fn test_unmarshal_ref_known_good_data() {
    // This is the raw binary data for a <success> node, as the decoder expects it (NO flag byte).
    let success_node_binary_no_flag =
        hex::decode("f80f4c1aff0517520218905cee043dfc0366726376f7012aff88236395184570386f4becb43cff051752020041ece6fc2c643559623557784c2b6b35554b5148564936627546524751456a30475a413565767a3862365632786b64773d").unwrap();

    // Call unmarshal_ref and inspect the borrowed view directly.
    let node_ref =
        unmarshal_ref(&success_node_binary_no_flag).expect("Should unmarshal_ref known good data");

    // Assert on the borrowed data without creating an owned Node.
    assert_eq!(node_ref.tag, "success");
    assert_eq!(node_ref.attrs.get("location").unwrap().as_ref(), "frc");
    assert_eq!(node_ref.attrs.get("props").unwrap().as_ref(), "27");
}

#[test]
fn test_unmarshal_ref_leftover_data_error() {
    let node_to_marshal = Node {
        tag: "test".to_string(),
        ..Default::default()
    };

    // Construct the data that unmarshal_ref will receive.
    let marshaled_with_flag = marshal(&node_to_marshal).expect("Marshal failed");

    // Remove the flag and append junk data.
    let mut raw_node_data = marshaled_with_flag[1..].to_vec();
    raw_node_data.extend_from_slice(&[1, 2, 3]);

    // Now, call unmarshal_ref with the malformed raw data.
    let result = unmarshal_ref(&raw_node_data);
    assert!(result.is_err());

    if let Err(e) = result {
        match e {
            wacore::binary::BinaryError::LeftoverData(n) => assert_eq!(n, 3),
            _ => panic!("Expected LeftoverData error, got {e:?}"),
        }
    }
}
