use crate::binary::{
    builder::NodeBuilder,
    marshal,
    node::{Node, NodeContent},
    unmarshal_ref,
};
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

use crate::wasm_types::WasmNode;

fn to_wasm_node(node: &Node) -> WasmNode {
    let content = match &node.content {
        Some(NodeContent::Nodes(nodes)) => Some(nodes.iter().map(to_wasm_node).collect()),
        _ => None,
    };
    WasmNode {
        tag: node.tag.clone(),
        attrs: node.attrs.clone(),
        content,
    }
}

fn to_internal_node(wasm_node: &WasmNode) -> Node {
    let mut builder = NodeBuilder::new(wasm_node.tag.clone()).attrs(wasm_node.attrs.clone());

    if let Some(children) = &wasm_node.content {
        builder = builder.children(children.iter().map(to_internal_node));
    }

    builder.build()
}

#[wasm_bindgen(js_name = marshal)]
pub fn marshal_node(node_val: JsValue) -> Result<Vec<u8>, JsValue> {
    let wasm_node: WasmNode =
        serde_wasm_bindgen::from_value(node_val).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let internal_node = to_internal_node(&wasm_node);

    marshal(&internal_node).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen(js_name = unmarshal)]
pub fn unmarshal_node(data: &[u8]) -> Result<JsValue, JsValue> {
    let node_ref = unmarshal_ref(data).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let owned_node = node_ref.to_owned();
    let wasm_node = to_wasm_node(&owned_node);

    serde_wasm_bindgen::to_value(&wasm_node).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen(js_name = NodeBuilder)]
pub struct WasmNodeBuilder {
    tag: String,
    attrs: HashMap<String, String>,
    content: Option<NodeContent>,
}

#[wasm_bindgen(js_class = NodeBuilder)]
impl WasmNodeBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new(tag: String) -> Self {
        Self {
            tag,
            attrs: HashMap::new(),
            content: None,
        }
    }

    pub fn attr(mut self, key: String, value: String) -> Self {
        self.attrs.insert(key, value);
        self
    }

    #[wasm_bindgen(js_name = children)]
    pub fn set_children(mut self, children_val: JsValue) -> Result<WasmNodeBuilder, JsValue> {
        let wasm_nodes: Vec<WasmNode> = serde_wasm_bindgen::from_value(children_val)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let internal_nodes = wasm_nodes.iter().map(to_internal_node).collect();
        self.content = Some(NodeContent::Nodes(internal_nodes));
        Ok(self)
    }

    #[wasm_bindgen(js_name = bytes)]
    pub fn set_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.content = Some(NodeContent::Bytes(bytes));
        self
    }

    pub fn build(self) -> Result<Vec<u8>, JsValue> {
        let node = Node {
            tag: self.tag,
            attrs: self.attrs,
            content: self.content,
        };
        marshal(&node).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}
