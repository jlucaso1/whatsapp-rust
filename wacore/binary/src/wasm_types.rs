use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const T_NODE: &'static str = r#"
/**
 * Represents a node structure for marshalling and unmarshalling.
 * This is the plain JavaScript object representation.
 */
export interface INode {
    tag: string;
    attrs?: Record<string, string>;
    content?: INode[];
}
"#;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WasmNode {
    pub tag: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub attrs: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Vec<WasmNode>>,
}
