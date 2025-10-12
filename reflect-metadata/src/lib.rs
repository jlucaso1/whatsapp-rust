#![no_std]

/// Description of a Rust type that can be reflected into bindings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeDescriptor {
    pub name: &'static str,
    pub module_path: &'static str,
    pub kind: TypeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeKind {
    Struct(&'static StructDescriptor),
    Enum(&'static EnumDescriptor),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StructDescriptor {
    pub fields: &'static [FieldDescriptor],
    pub style: StructStyle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructStyle {
    Unit,
    Tuple,
    Named,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnumDescriptor {
    pub variants: &'static [VariantDescriptor],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldDescriptor {
    pub name: &'static str,
    pub ty: &'static TypeExpr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VariantDescriptor {
    pub name: &'static str,
    pub fields: &'static [FieldDescriptor],
    pub style: StructStyle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeExpr {
    Primitive(PrimitiveType),
    Named(&'static str),
    Optional(&'static TypeExpr),
    Sequence(&'static TypeExpr),
    Map {
        key: &'static TypeExpr,
        value: &'static TypeExpr,
    },
    Tuple(&'static [&'static TypeExpr]),
    Unit,
    /// We could not model this type; treat it as opaque.
    Opaque(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimitiveType {
    Bool,
    I8,
    I16,
    I32,
    I64,
    U8,
    U16,
    U32,
    U64,
    F32,
    F64,
    String,
    Bytes,
}

impl PrimitiveType {
    pub const fn rust_name(self) -> &'static str {
        match self {
            PrimitiveType::Bool => "bool",
            PrimitiveType::I8 => "i8",
            PrimitiveType::I16 => "i16",
            PrimitiveType::I32 => "i32",
            PrimitiveType::I64 => "i64",
            PrimitiveType::U8 => "u8",
            PrimitiveType::U16 => "u16",
            PrimitiveType::U32 => "u32",
            PrimitiveType::U64 => "u64",
            PrimitiveType::F32 => "f32",
            PrimitiveType::F64 => "f64",
            PrimitiveType::String => "String",
            PrimitiveType::Bytes => "Vec<u8>",
        }
    }
}

pub trait Reflect {
    fn descriptor() -> &'static TypeDescriptor;
}
