use std::{env, fs, path::PathBuf};

use reflect_metadata::{FieldDescriptor, PrimitiveType, StructStyle, TypeExpr, TypeKind};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../src/ffi_reflect.rs");

    let binding_descriptors = whatsapp_rust::ffi_reflect::descriptors();

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let src_dir = manifest_dir.join("src");
    let udl_path = src_dir.join("whatsapp.udl");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let bindings_path = out_dir.join("bindings.rs");

    fs::create_dir_all(&src_dir).expect("create src dir");

    let mut rust =
        String::from("#[allow(unused_imports)]\npub mod generated {\n    use super::*;\n\n");
    let mut record_lines = Vec::new();
    let mut function_lines = Vec::new();

    for binding in binding_descriptors {
        let descriptor = binding.descriptor;
        match descriptor.kind {
            TypeKind::Struct(struct_desc) => {
                if !matches!(struct_desc.style, StructStyle::Named | StructStyle::Unit) {
                    panic!("only named or unit structs supported in prototype");
                }

                let proxy_name = format!("{}Proxy", descriptor.name);
                let proxy_fields = build_proxy_fields(struct_desc.fields);
                let original_path = binding.rust_path;

                rust.push_str(&format!(
                    "    #[derive(Clone, Debug, uniffi::Record)]\n    pub struct {proxy_name} {{\n{fields}    }}\n\n",
                    proxy_name = proxy_name,
                    fields = proxy_fields
                        .iter()
                        .map(|(name, ty, _)| format!("        pub {name}: {ty},\n"))
                        .collect::<String>(),
                ));

                rust.push_str(&generate_from_impl(
                    &proxy_name,
                    original_path,
                    &proxy_fields,
                ));
                rust.push_str(&generate_into_impl(
                    &proxy_name,
                    original_path,
                    &proxy_fields,
                ));

                let udl_fields = proxy_fields
                    .iter()
                    .map(|(name, _, udl_ty)| format!("    {udl_ty} {name};\n"))
                    .collect::<String>();

                record_lines.push(format!(
                    "dictionary {proxy_name} {{\n{udl_fields}}};",
                    proxy_name = proxy_name,
                    udl_fields = udl_fields,
                ));
            }
            TypeKind::Enum(_) => panic!("enums are not implemented in this prototype"),
        }
    }

    rust.push_str("}\n\npub use generated::*;\n");

    function_lines.push("    PublicDeviceStatusProxy sample_device_status();".to_string());
    function_lines.push("    PublicEventProxy sample_event();".to_string());

    let mut udl_sections = vec!["namespace whatsapp{};".to_string()];
    udl_sections.extend(record_lines);
    if !function_lines.is_empty() {
        let interface_body = function_lines.join("\n");
        udl_sections.push(format!(
            "interface WhatsappApi {{\n{interface_body}\n}};",
            interface_body = interface_body
        ));
    }

    let udl = format!("{}\n", udl_sections.join("\n\n"));

    fs::write(&udl_path, udl).expect("write udl");
    fs::write(&bindings_path, rust).expect("write bindings");

    uniffi::generate_scaffolding(udl_path.to_str().expect("udl path"))
        .expect("generate uniffi scaffolding");
}

fn build_proxy_fields(fields: &[FieldDescriptor]) -> Vec<(String, String, String)> {
    fields
        .iter()
        .map(|field| {
            let rust_type = type_expr_to_rust(field.ty);
            let udl_type = type_expr_to_udl(field.ty);
            (field.name.to_string(), rust_type, udl_type)
        })
        .collect()
}

fn type_expr_to_rust(expr: &TypeExpr) -> String {
    match expr {
        TypeExpr::Primitive(PrimitiveType::String) => "String".to_owned(),
        TypeExpr::Primitive(PrimitiveType::Bool) => "bool".to_owned(),
        TypeExpr::Primitive(PrimitiveType::I8) => "i8".to_owned(),
        TypeExpr::Primitive(PrimitiveType::I16) => "i16".to_owned(),
        TypeExpr::Primitive(PrimitiveType::I32) => "i32".to_owned(),
        TypeExpr::Primitive(PrimitiveType::I64) => "i64".to_owned(),
        TypeExpr::Primitive(PrimitiveType::U8) => "u8".to_owned(),
        TypeExpr::Primitive(PrimitiveType::U16) => "u16".to_owned(),
        TypeExpr::Primitive(PrimitiveType::U32) => "u32".to_owned(),
        TypeExpr::Primitive(PrimitiveType::U64) => "u64".to_owned(),
        TypeExpr::Primitive(PrimitiveType::F32) => "f32".to_owned(),
        TypeExpr::Primitive(PrimitiveType::F64) => "f64".to_owned(),
        TypeExpr::Primitive(PrimitiveType::Bytes) => "Vec<u8>".to_owned(),
        TypeExpr::Optional(inner) => format!("Option<{}>", type_expr_to_rust(inner)),
        TypeExpr::Sequence(inner) => format!("Vec<{}>", type_expr_to_rust(inner)),
        TypeExpr::Map { key, value } => format!(
            "std::collections::HashMap<{}, {}>",
            type_expr_to_rust(key),
            type_expr_to_rust(value)
        ),
        TypeExpr::Tuple(items) => {
            let inner = items
                .iter()
                .map(|ty| type_expr_to_rust(ty))
                .collect::<Vec<_>>()
                .join(", ");
            format!("({inner})")
        }
        TypeExpr::Unit => "()".to_owned(),
        TypeExpr::Named(name) | TypeExpr::Opaque(name) => name.to_string(),
    }
}

fn type_expr_to_udl(expr: &TypeExpr) -> String {
    match expr {
        TypeExpr::Primitive(PrimitiveType::String) => "string".to_owned(),
        TypeExpr::Primitive(PrimitiveType::Bool) => "boolean".to_owned(),
        TypeExpr::Primitive(PrimitiveType::I8) => "i8".to_owned(),
        TypeExpr::Primitive(PrimitiveType::I16) => "i16".to_owned(),
        TypeExpr::Primitive(PrimitiveType::I32) => "i32".to_owned(),
        TypeExpr::Primitive(PrimitiveType::I64) => "i64".to_owned(),
        TypeExpr::Primitive(PrimitiveType::U8) => "u8".to_owned(),
        TypeExpr::Primitive(PrimitiveType::U16) => "u16".to_owned(),
        TypeExpr::Primitive(PrimitiveType::U32) => "u32".to_owned(),
        TypeExpr::Primitive(PrimitiveType::U64) => "u64".to_owned(),
        TypeExpr::Primitive(PrimitiveType::F32) => "f32".to_owned(),
        TypeExpr::Primitive(PrimitiveType::F64) => "f64".to_owned(),
        TypeExpr::Primitive(PrimitiveType::Bytes) => "sequence<u8>".to_owned(),
        TypeExpr::Optional(inner) => format!("{}?", type_expr_to_udl(inner)),
        TypeExpr::Sequence(inner) => format!("sequence<{}>", type_expr_to_udl(inner)),
        TypeExpr::Map { key, value } => format!(
            "dictionary<{}, {}>",
            type_expr_to_udl(key),
            type_expr_to_udl(value)
        ),
        TypeExpr::Tuple(items) => {
            let inner = items
                .iter()
                .map(|ty| type_expr_to_udl(ty))
                .collect::<Vec<_>>()
                .join(", ");
            format!("({inner})")
        }
        TypeExpr::Unit => "void".to_owned(),
        TypeExpr::Named(name) | TypeExpr::Opaque(name) => name.to_string(),
    }
}

fn generate_from_impl(
    proxy_name: &str,
    original_path: &str,
    fields: &[(String, String, String)],
) -> String {
    let assignments = fields
        .iter()
        .map(|(name, _, _)| format!("            {name}: value.{name},\n"))
        .collect::<String>();

    format!(
        "    impl From<{original_path}> for {proxy_name} {{\n        fn from(value: {original_path}) -> Self {{\n            Self {{\n{assignments}            }}\n        }}\n    }}\n\n",
        original_path = original_path,
        proxy_name = proxy_name,
        assignments = assignments
    )
}

fn generate_into_impl(
    proxy_name: &str,
    original_path: &str,
    fields: &[(String, String, String)],
) -> String {
    let assignments = fields
        .iter()
        .map(|(name, _, _)| format!("            {name}: value.{name},\n"))
        .collect::<String>();

    format!(
        "    impl From<{proxy_name}> for {original_path} {{\n        fn from(value: {proxy_name}) -> Self {{\n            {original_path} {{\n{assignments}            }}\n        }}\n    }}\n\n",
        original_path = original_path,
        proxy_name = proxy_name,
        assignments = assignments
    )
}
