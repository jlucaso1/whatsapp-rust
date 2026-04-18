//! Derive macros for wacore protocol types.
//!
//! This crate provides derive macros for implementing the `ProtocolNode` trait
//! on structs that represent WhatsApp protocol nodes.
//!
//! # Example
//!
//! ```ignore
//! use wacore_derive::{ProtocolNode, WireEnum};
//!
//! /// A query request node.
//! /// Wire format: `<query request="interactive"/>`
//! #[derive(ProtocolNode)]
//! #[protocol(tag = "query")]
//! pub struct QueryRequest {
//!     #[attr(name = "request", default = "interactive")]
//!     pub request_type: String,
//! }
//!
//! /// An enum with string representation.
//! #[derive(WireEnum)]
//! pub enum MemberAddMode {
//!     #[wire = "admin_add"]
//!     AdminAdd,
//!     #[wire = "all_member_add"]
//!     AllMemberAdd,
//! }
//! ```

use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, parse_macro_input};

/// Derive macro for implementing `ProtocolNode` on structs with attributes.
///
/// # Attributes
///
/// - `#[protocol(tag = "tagname")]` - Required. Specifies the XML tag name.
/// - `#[attr(name = "attrname")]` - Marks a String field as an XML attribute.
/// - `#[attr(name = "attrname", default = "value")]` - Attribute with default value.
///   For `Option<String>` fields, a default always yields `Some(default)`.
/// - `#[attr(name = "attrname", jid)]` - Marks a Jid field as a JID attribute (required).
/// - `#[attr(name = "attrname", jid, optional)]` - Marks an Option<Jid> field as optional.
/// - `#[attr(name = "attrname", string_enum)]` - Marks a field whose type derives `WireEnum` in unit-string mode (uses `as_str()`/`TryFrom`).
/// - `#[attr(name = "attrname", u64)]` - Marks a u64 numeric attribute.
/// - `#[attr(name = "attrname", u32)]` - Marks a u32 numeric attribute.
///   Numeric fields can also be `Option<u64>` / `Option<u32>` for optional attributes.
///
/// # Example
///
/// ```ignore
/// #[derive(ProtocolNode)]
/// #[protocol(tag = "message")]
/// pub struct MessageStanza {
///     #[attr(name = "from", jid)]
///     pub from: Jid,
///     
///     #[attr(name = "to", jid)]
///     pub to: Jid,
///     
///     #[attr(name = "id")]
///     pub id: String,
///     
///     #[attr(name = "sender_lid", jid, optional)]
///     pub sender_lid: Option<Jid>,
/// }
/// ```
#[proc_macro_derive(ProtocolNode, attributes(protocol, attr))]
pub fn derive_protocol_node(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = &input.ident;

    let tag = match extract_tag(&input.attrs) {
        Ok(Some(tag)) => tag,
        Ok(None) => {
            return syn::Error::new_spanned(
                &input.ident,
                "ProtocolNode requires #[protocol(tag = \"...\")]",
            )
            .to_compile_error()
            .into();
        }
        Err(e) => return e.to_compile_error().into(),
    };

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            Fields::Unit => return generate_empty_impl(name, &tag).into(),
            _ => {
                return syn::Error::new_spanned(
                    &input.ident,
                    "ProtocolNode only supports named fields or unit structs",
                )
                .to_compile_error()
                .into();
            }
        },
        _ => {
            return syn::Error::new_spanned(
                &input.ident,
                "ProtocolNode can only be derived for structs",
            )
            .to_compile_error()
            .into();
        }
    };

    let mut attr_fields = Vec::with_capacity(fields.len());
    for field in fields {
        match extract_attr_info(field) {
            Ok(Some(attr_info)) => attr_fields.push(attr_info),
            Ok(None) => {}
            Err(e) => return e.to_compile_error().into(),
        }
    }

    let attr_setters: Vec<_> = attr_fields
        .iter()
        .map(|info| {
            let field_ident = &info.field_ident;
            let attr_name = &info.attr_name;

            match (&info.attr_type, info.optional) {
                (AttrType::Jid, true) => {
                    quote! {
                        if let Some(jid) = self.#field_ident {
                            builder = builder.attr(#attr_name, jid);
                        }
                    }
                }
                (AttrType::Jid, false) => {
                    quote! {
                        builder = builder.attr(#attr_name, self.#field_ident);
                    }
                }
                (AttrType::String, true) => {
                    quote! {
                        if let Some(s) = self.#field_ident {
                            builder = builder.attr(#attr_name, s);
                        }
                    }
                }
                (AttrType::String, false) => {
                    quote! {
                        builder = builder.attr(#attr_name, self.#field_ident);
                    }
                }
                (AttrType::StringEnum, true) => {
                    quote! {
                        if let Some(ref v) = self.#field_ident {
                            builder = builder.attr(#attr_name, v.as_str());
                        }
                    }
                }
                (AttrType::StringEnum, false) => {
                    quote! {
                        builder = builder.attr(#attr_name, self.#field_ident.as_str());
                    }
                }
                (AttrType::U64, true) | (AttrType::U32, true) => {
                    quote! {
                        if let Some(v) = self.#field_ident {
                            builder = builder.attr(#attr_name, v.to_string());
                        }
                    }
                }
                (AttrType::U64, false) | (AttrType::U32, false) => {
                    quote! {
                        builder = builder.attr(#attr_name, self.#field_ident.to_string());
                    }
                }
            }
        })
        .collect();

    let field_parsers: Vec<_> = attr_fields
        .iter()
        .map(|info| {
            let field_ident = &info.field_ident;
            let attr_name = &info.attr_name;

            match (&info.attr_type, info.optional, &info.default) {
                (AttrType::Jid, false, _) => {
                    quote! {
                        #field_ident: node.attrs().optional_jid(#attr_name)
                            .ok_or_else(|| ::anyhow::anyhow!("missing required attribute '{}'", #attr_name))?
                    }
                }
                (AttrType::Jid, true, _) => {
                    quote! {
                        #field_ident: node.attrs().optional_jid(#attr_name)
                    }
                }
                (AttrType::String, false, Some(default)) => {
                    quote! {
                        #field_ident: node.attrs().optional_string(#attr_name)
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| #default.to_string())
                    }
                }
                (AttrType::String, false, None) => {
                    quote! {
                        #field_ident: node.attrs().required_string(#attr_name)?.to_string()
                    }
                }
                (AttrType::String, true, Some(default)) => {
                    quote! {
                        #field_ident: node.attrs().optional_string(#attr_name)
                            .map(|s| s.to_string())
                            .or_else(|| Some(#default.to_string()))
                    }
                }
                (AttrType::String, true, None) => {
                    quote! {
                        #field_ident: node.attrs().optional_string(#attr_name).map(|s| s.to_string())
                    }
                }
                // StringEnum: parse using the `parse_string_enum` helper which tries TryFrom then From.
                (AttrType::StringEnum, false, Some(default)) => {
                    quote! {
                        #field_ident: ::wacore::protocol::parse_string_enum(
                            node.attrs().optional_string(#attr_name).as_deref().unwrap_or(#default)
                        )?
                    }
                }
                (AttrType::StringEnum, false, None) => {
                    quote! {
                        #field_ident: ::wacore::protocol::parse_string_enum(
                            &node.attrs().optional_string(#attr_name)
                                .ok_or_else(|| ::anyhow::anyhow!("missing required attribute '{}'", #attr_name))?
                        )?
                    }
                }
                (AttrType::StringEnum, true, _) => {
                    quote! {
                        #field_ident: node.attrs().optional_string(#attr_name)
                            .map(|s| ::wacore::protocol::parse_string_enum(&s))
                            .transpose()?
                    }
                }
                // Numeric types
                (AttrType::U64, false, _) => {
                    quote! {
                        #field_ident: node.attrs().optional_u64(#attr_name)
                            .ok_or_else(|| ::anyhow::anyhow!("missing required attribute '{}'", #attr_name))?
                    }
                }
                (AttrType::U64, true, _) => {
                    quote! {
                        #field_ident: node.attrs().optional_u64(#attr_name)
                    }
                }
                (AttrType::U32, false, _) => {
                    quote! {
                        #field_ident: node.attrs().optional_u64(#attr_name)
                            .map(|v| u32::try_from(v))
                            .transpose()
                            .map_err(|_| ::anyhow::anyhow!("attribute '{}' value exceeds u32::MAX", #attr_name))?
                            .ok_or_else(|| ::anyhow::anyhow!("missing required attribute '{}'", #attr_name))?
                    }
                }
                (AttrType::U32, true, _) => {
                    quote! {
                        #field_ident: node.attrs().optional_u64(#attr_name)
                            .map(|v| u32::try_from(v))
                            .transpose()
                            .map_err(|_| ::anyhow::anyhow!("attribute '{}' value exceeds u32::MAX", #attr_name))?
                    }
                }
            }
        })
        .collect();

    // Only generate Default impl if all fields have defaults or are optional or have Default impl
    let all_have_defaults = attr_fields.iter().all(|info| {
        info.default.is_some() || info.optional || matches!(info.attr_type, AttrType::StringEnum)
    });

    let default_impl = if all_have_defaults {
        let default_fields: Vec<_> = attr_fields
            .iter()
            .map(|info| {
                let field_ident = &info.field_ident;
                match (&info.attr_type, info.optional, &info.default) {
                    (_, true, Some(default)) => quote! { #field_ident: Some(#default.to_string()) },
                    (_, true, None) => quote! { #field_ident: None },
                    (AttrType::String, false, Some(default)) => {
                        quote! { #field_ident: #default.to_string() }
                    }
                    (AttrType::StringEnum, false, Some(default)) => {
                        quote! { #field_ident: ::wacore::protocol::parse_string_enum(#default)
                        .expect("invalid default for StringEnum field") }
                    }
                    (AttrType::StringEnum, false, None) => {
                        quote! { #field_ident: ::core::default::Default::default() }
                    }
                    _ => unreachable!("all_have_defaults check should prevent this branch"),
                }
            })
            .collect();

        quote! {
            impl ::core::default::Default for #name {
                fn default() -> Self {
                    Self {
                        #(#default_fields),*
                    }
                }
            }
        }
    } else {
        quote! {}
    };

    let expanded = quote! {
        impl ::wacore::protocol::ProtocolNode for #name {
            fn tag(&self) -> &'static str {
                #tag
            }

            fn into_node(self) -> ::wacore_binary::node::Node {
                let mut builder = ::wacore_binary::builder::NodeBuilder::new(#tag);
                #(#attr_setters)*
                builder.build()
            }

            fn try_from_node_ref(node: &::wacore_binary::node::NodeRef<'_>) -> ::anyhow::Result<Self> {
                if node.tag != #tag {
                    return Err(::anyhow::anyhow!("expected <{}>, got <{}>", #tag, node.tag));
                }
                Ok(Self {
                    #(#field_parsers),*
                })
            }
        }

        #default_impl
    };

    expanded.into()
}

/// Derive macro for empty protocol nodes (tag only, no attributes).
///
/// # Attributes
///
/// - `#[protocol(tag = "tagname")]` - Required. Specifies the XML tag name.
///
/// # Example
///
/// ```ignore
/// #[derive(EmptyNode)]
/// #[protocol(tag = "participants")]
/// pub struct ParticipantsRequest;
/// ```
#[proc_macro_derive(EmptyNode, attributes(protocol))]
pub fn derive_empty_node(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = &input.ident;

    let tag = match extract_tag(&input.attrs) {
        Ok(Some(tag)) => tag,
        Ok(None) => {
            return syn::Error::new_spanned(
                &input.ident,
                "EmptyNode requires #[protocol(tag = \"...\")]",
            )
            .to_compile_error()
            .into();
        }
        Err(e) => return e.to_compile_error().into(),
    };

    generate_empty_impl(name, &tag).into()
}

fn generate_empty_impl(name: &syn::Ident, tag: &str) -> proc_macro2::TokenStream {
    quote! {
        impl ::wacore::protocol::ProtocolNode for #name {
            fn tag(&self) -> &'static str {
                #tag
            }

            fn into_node(self) -> ::wacore_binary::node::Node {
                ::wacore_binary::builder::NodeBuilder::new(#tag).build()
            }

            fn try_from_node_ref(node: &::wacore_binary::node::NodeRef<'_>) -> ::anyhow::Result<Self> {
                if node.tag != #tag {
                    return Err(::anyhow::anyhow!("expected <{}>, got <{}>", #tag, node.tag));
                }
                Ok(Self)
            }
        }

        impl ::core::default::Default for #name {
            fn default() -> Self {
                Self
            }
        }
    }
}

enum AttrType {
    String,
    Jid,
    /// A type implementing StringEnum (has `as_str()` and `TryFrom<&str>` or `From<&str>`).
    StringEnum,
    /// A u64 numeric attribute.
    U64,
    /// A u32 numeric attribute.
    U32,
}

struct AttrFieldInfo {
    field_ident: syn::Ident,
    attr_name: String,
    attr_type: AttrType,
    optional: bool,
    default: Option<String>,
}

fn extract_tag(attrs: &[syn::Attribute]) -> Result<Option<String>, syn::Error> {
    for attr in attrs {
        if attr.path().is_ident("protocol") {
            let mut tag = None;
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("tag") {
                    let value: syn::LitStr = meta.value()?.parse()?;
                    tag = Some(value.value());
                }
                Ok(())
            })?;
            if tag.is_some() {
                return Ok(tag);
            }
        }
    }
    Ok(None)
}

fn extract_attr_info(field: &syn::Field) -> Result<Option<AttrFieldInfo>, syn::Error> {
    let field_ident = match field.ident.clone() {
        Some(ident) => ident,
        None => return Ok(None),
    };

    // Check if field type is Option<T>
    let is_optional = is_option_type(&field.ty);

    for attr in &field.attrs {
        if attr.path().is_ident("attr") {
            let mut attr_name = None;
            let mut default = None;
            let mut is_jid = false;
            let mut is_string_enum = false;
            let mut is_u64 = false;
            let mut is_u32 = false;
            let mut explicit_optional = false;

            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("name") {
                    let value: syn::LitStr = meta.value()?.parse()?;
                    attr_name = Some(value.value());
                } else if meta.path.is_ident("default") {
                    let value: syn::LitStr = meta.value()?.parse()?;
                    default = Some(value.value());
                } else if meta.path.is_ident("jid") {
                    is_jid = true;
                } else if meta.path.is_ident("string_enum") {
                    is_string_enum = true;
                } else if meta.path.is_ident("u64") {
                    is_u64 = true;
                } else if meta.path.is_ident("u32") {
                    is_u32 = true;
                } else if meta.path.is_ident("optional") {
                    explicit_optional = true;
                }
                Ok(())
            })?;

            match attr_name {
                Some(name) => {
                    let attr_type = if is_jid {
                        AttrType::Jid
                    } else if is_string_enum {
                        AttrType::StringEnum
                    } else if is_u64 {
                        AttrType::U64
                    } else if is_u32 {
                        AttrType::U32
                    } else {
                        AttrType::String
                    };

                    // Determine if optional: either explicit marker or Option<T> type
                    let optional = explicit_optional || is_optional;

                    return Ok(Some(AttrFieldInfo {
                        field_ident,
                        attr_name: name,
                        attr_type,
                        optional,
                        default,
                    }));
                }
                None => {
                    return Err(syn::Error::new_spanned(
                        attr,
                        "missing required `name` in #[attr(...)]",
                    ));
                }
            }
        }
    }
    Ok(None)
}

/// Check if a type is Option<T>
fn is_option_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(type_path) = ty
        && let Some(segment) = type_path.path.segments.last()
    {
        return segment.ident == "Option";
    }
    false
}

// =====================================================================
// WireEnum — the unified replacement for StringEnum + manual impl Serialize
// for tagged-with-payload and int-discriminated enums.
//
// Modes, inferred from attributes:
//
//   1. unit-string  (default when no #[wire(tag=...)] and no #[wire(kind="int")])
//      Every variant is a unit (or a single #[wire_fallback] tuple with String).
//      Emits: as_str, TryFrom<&str>/From<&str>, Default, Display, Serialize,
//             Deserialize, ParseStringEnum. Drop-in replacement for StringEnum.
//
//   2. tagged       (enum has #[wire(tag = "type")])
//      Variants carry payload (named fields or unit). One #[wire = "..."] per
//      variant; optional #[wire_alias = "..."] adds parser-side aliases;
//      #[wire(skip)] on a field excludes it from JSON; #[wire_fallback] with
//      { tag: String } catches unknown tags.
//      Emits: wire_tag(), impl Serialize (SerializeMap), and a sibling
//             <Name>Tag unit enum (unit-string WireEnum) for parser dispatch.
//      No Deserialize — follow-up work; not needed by current consumers.
//
//   3. int          (enum has #[wire(kind = "int")])
//      Unit variants + optional #[wire_fallback] tuple with i32. Each variant
//      has #[wire = NUM].
//      Emits: code(), From<i32>, Serialize (as i32), Deserialize (from i32).
//
// The wire string/number lives exactly once per variant, in the #[wire = ...]
// attribute. Everything else is derived.
// =====================================================================

#[proc_macro_derive(WireEnum, attributes(wire, wire_alias, wire_default, wire_fallback))]
pub fn derive_wire_enum(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let variants = match &input.data {
        Data::Enum(e) => e.variants.clone(),
        _ => {
            return syn::Error::new_spanned(&input.ident, "WireEnum can only be derived for enums")
                .to_compile_error()
                .into();
        }
    };

    let cfg = match parse_enum_level_wire(&input.attrs) {
        Ok(c) => c,
        Err(e) => return e.to_compile_error().into(),
    };

    match cfg.kind {
        WireKind::IntTagged => expand_wire_enum_int(&input.ident, &variants).into(),
        WireKind::StringTagged(discriminator) => {
            expand_wire_enum_tagged(&input.ident, &variants, &discriminator).into()
        }
        WireKind::UnitString => expand_wire_enum_unit(&input.ident, &variants).into(),
    }
}

// ----- enum-level config -----

enum WireKind {
    UnitString,
    StringTagged(String),
    IntTagged,
}

struct WireEnumCfg {
    kind: WireKind,
}

fn parse_enum_level_wire(attrs: &[syn::Attribute]) -> syn::Result<WireEnumCfg> {
    let mut tag_field: Option<String> = None;
    let mut kind_is_int = false;

    for attr in attrs {
        if !attr.path().is_ident("wire") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("tag") {
                let lit: syn::LitStr = meta.value()?.parse()?;
                tag_field = Some(lit.value());
            } else if meta.path.is_ident("kind") {
                let lit: syn::LitStr = meta.value()?.parse()?;
                match lit.value().as_str() {
                    "int" => kind_is_int = true,
                    "string" => kind_is_int = false,
                    other => {
                        return Err(meta.error(format!(
                            "unknown wire kind {other:?}; expected \"string\" or \"int\""
                        )));
                    }
                }
            } else {
                return Err(meta.error("unknown attribute inside #[wire(...)]"));
            }
            Ok(())
        })?;
    }

    let kind = if kind_is_int {
        if tag_field.is_some() {
            return Err(syn::Error::new_spanned(
                &attrs[0],
                "#[wire(kind = \"int\")] is incompatible with #[wire(tag = \"...\")]",
            ));
        }
        WireKind::IntTagged
    } else if let Some(t) = tag_field {
        WireKind::StringTagged(t)
    } else {
        WireKind::UnitString
    };

    Ok(WireEnumCfg { kind })
}

// ----- variant-level helpers -----

enum VariantWire {
    Str(String),
    Int(i32),
}

struct VariantInfo {
    ident: syn::Ident,
    fields: syn::Fields,
    wire: Option<VariantWire>,
    aliases: Vec<String>,
    is_default: bool,
    is_fallback: bool,
}

fn read_variant(v: &syn::Variant) -> syn::Result<VariantInfo> {
    let mut wire: Option<VariantWire> = None;
    let mut aliases: Vec<String> = Vec::new();
    let mut is_default = false;
    let mut is_fallback = false;

    for attr in &v.attrs {
        if attr.path().is_ident("wire_default") {
            is_default = true;
        } else if attr.path().is_ident("wire_fallback") {
            is_fallback = true;
        } else if attr.path().is_ident("wire_alias") {
            if let syn::Meta::NameValue(nv) = &attr.meta
                && let syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(s),
                    ..
                }) = &nv.value
            {
                aliases.push(s.value());
            } else {
                return Err(syn::Error::new_spanned(
                    attr,
                    "expected #[wire_alias = \"...\"] with a string literal",
                ));
            }
        } else if attr.path().is_ident("wire") {
            // Variant-level #[wire = "..."] or #[wire = 101]
            if let syn::Meta::NameValue(nv) = &attr.meta {
                match &nv.value {
                    syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Str(s),
                        ..
                    }) => wire = Some(VariantWire::Str(s.value())),
                    syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Int(n),
                        ..
                    }) => {
                        // Reject out-of-range literals at macro parse time rather
                        // than silently wrapping with `as i32`.
                        let parsed: i32 = n.base10_parse().map_err(|_| {
                            syn::Error::new_spanned(
                                n,
                                format!(
                                    "#[wire = {}] does not fit in i32 ({}..={})",
                                    n,
                                    i32::MIN,
                                    i32::MAX
                                ),
                            )
                        })?;
                        wire = Some(VariantWire::Int(parsed));
                    }
                    _ => {
                        return Err(syn::Error::new_spanned(
                            &nv.value,
                            "#[wire = ...] expects a string or integer literal",
                        ));
                    }
                }
            }
        }
    }

    Ok(VariantInfo {
        ident: v.ident.clone(),
        fields: v.fields.clone(),
        wire,
        aliases,
        is_default,
        is_fallback,
    })
}

fn field_has_wire_skip(attrs: &[syn::Attribute]) -> bool {
    for attr in attrs {
        if !attr.path().is_ident("wire") {
            continue;
        }
        let mut found_skip = false;
        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("skip") {
                found_skip = true;
            }
            Ok(())
        });
        if found_skip {
            return true;
        }
    }
    false
}

// ================== unit-string mode ==================

fn expand_wire_enum_unit(
    name: &syn::Ident,
    variants: &syn::punctuated::Punctuated<syn::Variant, syn::Token![,]>,
) -> proc_macro2::TokenStream {
    let mut infos = Vec::with_capacity(variants.len());
    for v in variants {
        match read_variant(v) {
            Ok(info) => infos.push(info),
            Err(e) => return e.to_compile_error(),
        }
    }

    let mut seen: std::collections::HashMap<String, syn::Ident> = Default::default();
    let mut fallback: Option<&VariantInfo> = None;
    let mut default_variant: Option<&VariantInfo> = None;

    for info in &infos {
        if info.is_fallback {
            if fallback.is_some() {
                return syn::Error::new_spanned(
                    &info.ident,
                    "only one #[wire_fallback] variant is allowed",
                )
                .to_compile_error();
            }
            match &info.fields {
                syn::Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {}
                _ => {
                    return syn::Error::new_spanned(
                        &info.ident,
                        "#[wire_fallback] on a unit-string enum requires VariantName(String)",
                    )
                    .to_compile_error();
                }
            }
            if info.wire.is_some() {
                return syn::Error::new_spanned(
                    &info.ident,
                    "#[wire_fallback] variant must not carry #[wire = \"...\"]",
                )
                .to_compile_error();
            }
            fallback = Some(info);
            if info.is_default {
                default_variant = Some(info);
            }
            continue;
        }
        if !matches!(info.fields, syn::Fields::Unit) {
            return syn::Error::new_spanned(
                &info.ident,
                "unit-string WireEnum only supports unit variants (use #[wire_fallback] for a catch-all)",
            )
            .to_compile_error();
        }
        let Some(VariantWire::Str(s)) = &info.wire else {
            return syn::Error::new_spanned(&info.ident, "variant needs #[wire = \"...\"]")
                .to_compile_error();
        };
        if let Some(prev) = seen.insert(s.clone(), info.ident.clone()) {
            return syn::Error::new_spanned(
                &info.ident,
                format!("duplicate #[wire = \"{s}\"]; already used by {prev}"),
            )
            .to_compile_error();
        }
        if info.is_default {
            if default_variant.is_some() {
                return syn::Error::new_spanned(&info.ident, "only one #[wire_default] is allowed")
                    .to_compile_error();
            }
            default_variant = Some(info);
        }
        for alias in &info.aliases {
            if let Some(prev) = seen.insert(alias.clone(), info.ident.clone()) {
                return syn::Error::new_spanned(
                    &info.ident,
                    format!(
                        "#[wire_alias = \"{alias}\"] collides with existing wire tag from variant {prev}"
                    ),
                )
                .to_compile_error();
            }
        }
    }

    let first_known: Option<&VariantInfo> = infos.iter().find(|i| !i.is_fallback);
    let default_info = match (default_variant, first_known, fallback) {
        (Some(d), _, _) => d,
        (None, Some(f), _) => f,
        (None, None, Some(fb)) => fb,
        (None, None, None) => {
            return syn::Error::new_spanned(name, "WireEnum cannot be derived for empty enums")
                .to_compile_error();
        }
    };
    let default_ident = &default_info.ident;
    let default_ctor = if default_info.is_fallback {
        quote! { #name::#default_ident(::std::string::String::new()) }
    } else {
        quote! { #name::#default_ident }
    };

    let known: Vec<(&syn::Ident, &String)> = infos
        .iter()
        .filter(|i| !i.is_fallback)
        .map(|i| {
            let VariantWire::Str(s) = i.wire.as_ref().unwrap() else {
                unreachable!()
            };
            (&i.ident, s)
        })
        .collect();

    // `as_str()` always returns the PRIMARY tag — aliases are parser-only and
    // must never surface in serialization.
    let as_str_arms: Vec<_> = known
        .iter()
        .map(|(id, s)| quote! { #name::#id => #s })
        .collect();

    // For parsing, include primary + each alias; all map to the same variant.
    let try_from_arms: Vec<proc_macro2::TokenStream> = infos
        .iter()
        .filter(|i| !i.is_fallback)
        .flat_map(|i| {
            let id = &i.ident;
            let VariantWire::Str(primary) = i.wire.as_ref().unwrap() else {
                unreachable!()
            };
            std::iter::once(primary.clone())
                .chain(i.aliases.iter().cloned())
                .map(move |s| quote! { #s => ::core::result::Result::Ok(#name::#id) })
        })
        .collect();

    let from_arms: Vec<proc_macro2::TokenStream> = infos
        .iter()
        .filter(|i| !i.is_fallback)
        .flat_map(|i| {
            let id = &i.ident;
            let VariantWire::Str(primary) = i.wire.as_ref().unwrap() else {
                unreachable!()
            };
            std::iter::once(primary.clone())
                .chain(i.aliases.iter().cloned())
                .map(move |s| quote! { #s => #name::#id })
        })
        .collect();

    let as_str_return_ty;
    let as_str_block;
    let conversion_impls;

    if let Some(fb) = fallback {
        let fb_ident = &fb.ident;
        as_str_return_ty = quote! { &str };
        as_str_block = quote! {
            match self {
                #(#as_str_arms,)*
                #name::#fb_ident(s) => s.as_str(),
            }
        };
        conversion_impls = quote! {
            impl ::core::convert::From<&str> for #name {
                fn from(value: &str) -> Self {
                    match value {
                        #(#from_arms,)*
                        other => #name::#fb_ident(other.to_string()),
                    }
                }
            }

            impl ::wacore::protocol::ParseStringEnum for #name {
                fn parse_from_str(s: &str) -> ::anyhow::Result<Self> {
                    ::core::result::Result::Ok(::core::convert::From::from(s))
                }
            }
        };
    } else {
        as_str_return_ty = quote! { &'static str };
        as_str_block = quote! {
            match self {
                #(#as_str_arms),*
            }
        };
        conversion_impls = quote! {
            impl ::core::convert::TryFrom<&str> for #name {
                type Error = ::anyhow::Error;
                fn try_from(value: &str) -> ::core::result::Result<Self, Self::Error> {
                    match value {
                        #(#try_from_arms),*,
                        _ => ::core::result::Result::Err(
                            ::anyhow::anyhow!("unknown {}: {}", stringify!(#name), value)
                        ),
                    }
                }
            }

            impl ::wacore::protocol::ParseStringEnum for #name {
                fn parse_from_str(s: &str) -> ::anyhow::Result<Self> {
                    ::core::convert::TryFrom::try_from(s)
                }
            }
        };
    }

    let deserialize_impl = if fallback.is_some() {
        quote! {
            impl<'de> ::serde::Deserialize<'de> for #name {
                fn deserialize<D: ::serde::Deserializer<'de>>(
                    deserializer: D,
                ) -> ::core::result::Result<Self, D::Error> {
                    let s = <::std::string::String as ::serde::Deserialize>::deserialize(deserializer)?;
                    ::core::result::Result::Ok(<Self as ::core::convert::From<&str>>::from(s.as_str()))
                }
            }
        }
    } else {
        quote! {
            impl<'de> ::serde::Deserialize<'de> for #name {
                fn deserialize<D: ::serde::Deserializer<'de>>(
                    deserializer: D,
                ) -> ::core::result::Result<Self, D::Error> {
                    let s = <::std::string::String as ::serde::Deserialize>::deserialize(deserializer)?;
                    <Self as ::core::convert::TryFrom<&str>>::try_from(s.as_str())
                        .map_err(|e| <D::Error as ::serde::de::Error>::custom(e.to_string()))
                }
            }
        }
    };

    quote! {
        impl #name {
            /// Wire string for this variant (single source of truth).
            pub fn as_str(&self) -> #as_str_return_ty {
                #as_str_block
            }
        }

        impl ::core::fmt::Display for #name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        #conversion_impls

        impl ::core::default::Default for #name {
            fn default() -> Self {
                #default_ctor
            }
        }

        impl ::serde::Serialize for #name {
            fn serialize<S: ::serde::Serializer>(
                &self,
                serializer: S,
            ) -> ::core::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        #deserialize_impl
    }
}

// ================== int mode ==================

fn expand_wire_enum_int(
    name: &syn::Ident,
    variants: &syn::punctuated::Punctuated<syn::Variant, syn::Token![,]>,
) -> proc_macro2::TokenStream {
    let mut infos = Vec::with_capacity(variants.len());
    for v in variants {
        match read_variant(v) {
            Ok(info) => infos.push(info),
            Err(e) => return e.to_compile_error(),
        }
    }

    let mut fallback: Option<&VariantInfo> = None;
    let mut seen: std::collections::HashMap<i32, syn::Ident> = Default::default();

    for info in &infos {
        if info.is_fallback {
            if fallback.is_some() {
                return syn::Error::new_spanned(
                    &info.ident,
                    "only one #[wire_fallback] is allowed",
                )
                .to_compile_error();
            }
            match &info.fields {
                syn::Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {}
                _ => {
                    return syn::Error::new_spanned(
                        &info.ident,
                        "#[wire_fallback] in int mode requires VariantName(i32)",
                    )
                    .to_compile_error();
                }
            }
            fallback = Some(info);
            continue;
        }
        if !matches!(info.fields, syn::Fields::Unit) {
            return syn::Error::new_spanned(
                &info.ident,
                "int-mode WireEnum variants must be unit variants (except the #[wire_fallback])",
            )
            .to_compile_error();
        }
        let Some(VariantWire::Int(n)) = &info.wire else {
            return syn::Error::new_spanned(&info.ident, "variant needs #[wire = NUMBER]")
                .to_compile_error();
        };
        if let Some(prev) = seen.insert(*n, info.ident.clone()) {
            return syn::Error::new_spanned(
                &info.ident,
                format!("duplicate #[wire = {n}]; already used by {prev}"),
            )
            .to_compile_error();
        }
    }

    let Some(fb) = fallback else {
        return syn::Error::new_spanned(
            name,
            "int-mode WireEnum requires a #[wire_fallback] variant like Unknown(i32)",
        )
        .to_compile_error();
    };
    let fb_ident = &fb.ident;

    let code_arms: Vec<_> = infos
        .iter()
        .filter(|i| !i.is_fallback)
        .map(|i| {
            let id = &i.ident;
            let VariantWire::Int(n) = i.wire.as_ref().unwrap() else {
                unreachable!()
            };
            let lit = proc_macro2::Literal::i32_suffixed(*n);
            quote! { #name::#id => #lit }
        })
        .collect();

    let from_arms: Vec<_> = infos
        .iter()
        .filter(|i| !i.is_fallback)
        .map(|i| {
            let id = &i.ident;
            let VariantWire::Int(n) = i.wire.as_ref().unwrap() else {
                unreachable!()
            };
            let lit = proc_macro2::Literal::i32_suffixed(*n);
            quote! { #lit => #name::#id }
        })
        .collect();

    quote! {
        impl #name {
            /// Numeric wire code for this variant (single source of truth).
            pub fn code(&self) -> i32 {
                match self {
                    #(#code_arms,)*
                    #name::#fb_ident(n) => *n,
                }
            }
        }

        impl ::core::convert::From<i32> for #name {
            fn from(code: i32) -> Self {
                match code {
                    #(#from_arms,)*
                    other => #name::#fb_ident(other),
                }
            }
        }

        impl ::serde::Serialize for #name {
            fn serialize<S: ::serde::Serializer>(
                &self,
                serializer: S,
            ) -> ::core::result::Result<S::Ok, S::Error> {
                serializer.serialize_i32(self.code())
            }
        }

        impl<'de> ::serde::Deserialize<'de> for #name {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> ::core::result::Result<Self, D::Error> {
                let n = <i32 as ::serde::Deserialize>::deserialize(deserializer)?;
                ::core::result::Result::Ok(<Self as ::core::convert::From<i32>>::from(n))
            }
        }
    }
}

// ================== tagged mode ==================

fn expand_wire_enum_tagged(
    name: &syn::Ident,
    variants: &syn::punctuated::Punctuated<syn::Variant, syn::Token![,]>,
    discriminator: &str,
) -> proc_macro2::TokenStream {
    let mut infos = Vec::with_capacity(variants.len());
    for v in variants {
        match read_variant(v) {
            Ok(info) => infos.push(info),
            Err(e) => return e.to_compile_error(),
        }
    }

    let mut seen: std::collections::HashMap<String, syn::Ident> = Default::default();
    let mut fallback: Option<&VariantInfo> = None;

    for info in &infos {
        if info.is_fallback {
            if fallback.is_some() {
                return syn::Error::new_spanned(
                    &info.ident,
                    "only one #[wire_fallback] is allowed",
                )
                .to_compile_error();
            }
            // Must be { tag: String }
            let ok = matches!(
                &info.fields,
                syn::Fields::Named(n)
                    if n.named.len() == 1
                        && n.named
                            .first()
                            .unwrap()
                            .ident
                            .as_ref()
                            .map(|i| i == "tag")
                            .unwrap_or(false)
            );
            if !ok {
                return syn::Error::new_spanned(
                    &info.ident,
                    "tagged #[wire_fallback] must have exactly { tag: String }",
                )
                .to_compile_error();
            }
            if info.wire.is_some() {
                return syn::Error::new_spanned(
                    &info.ident,
                    "#[wire_fallback] variant must not have #[wire = \"...\"]",
                )
                .to_compile_error();
            }
            fallback = Some(info);
            continue;
        }
        let Some(VariantWire::Str(s)) = &info.wire else {
            return syn::Error::new_spanned(&info.ident, "variant needs #[wire = \"...\"]")
                .to_compile_error();
        };
        if let Some(prev) = seen.insert(s.clone(), info.ident.clone()) {
            return syn::Error::new_spanned(
                &info.ident,
                format!("duplicate #[wire = \"{s}\"]; already used by {prev}"),
            )
            .to_compile_error();
        }
        for alias in &info.aliases {
            if let Some(prev) = seen.insert(alias.clone(), info.ident.clone()) {
                return syn::Error::new_spanned(
                    &info.ident,
                    format!(
                        "#[wire_alias = \"{alias}\"] collides with wire tag from variant {prev}"
                    ),
                )
                .to_compile_error();
            }
        }
    }

    // --- wire_tag(&self) -> &str ---

    let wire_tag_arms: Vec<_> = infos
        .iter()
        .map(|info| {
            let id = &info.ident;
            if info.is_fallback {
                // { tag: String } — return borrowed from the field
                quote! { #name::#id { tag } => tag.as_str() }
            } else {
                let VariantWire::Str(s) = info.wire.as_ref().unwrap() else {
                    unreachable!()
                };
                match &info.fields {
                    syn::Fields::Unit => quote! { #name::#id => #s },
                    syn::Fields::Named(_) => quote! { #name::#id { .. } => #s },
                    syn::Fields::Unnamed(_) => quote! { #name::#id(..) => #s },
                }
            }
        })
        .collect();

    // --- Serialize arms ---

    let serialize_arms: Vec<_> = infos
        .iter()
        .map(|info| {
            let id = &info.ident;
            if info.is_fallback {
                // Only the discriminator is written (already done before match).
                quote! { #name::#id { tag: _ } => {} }
            } else {
                match &info.fields {
                    syn::Fields::Unit => quote! { #name::#id => {} },
                    syn::Fields::Named(named) => {
                        let bindings: Vec<proc_macro2::TokenStream> = named
                            .named
                            .iter()
                            .map(|f| {
                                let id = f.ident.as_ref().unwrap();
                                if field_has_wire_skip(&f.attrs) {
                                    quote! { #id: _ }
                                } else {
                                    quote! { #id }
                                }
                            })
                            .collect();
                        let entries: Vec<proc_macro2::TokenStream> = named
                            .named
                            .iter()
                            .filter(|f| !field_has_wire_skip(&f.attrs))
                            .map(|f| {
                                let id = f.ident.as_ref().unwrap();
                                let key = id.to_string();
                                if is_option_type(&f.ty) {
                                    quote! {
                                        if let ::core::option::Option::Some(__v) = #id {
                                            ::serde::ser::SerializeMap::serialize_entry(
                                                &mut map, #key, __v
                                            )?;
                                        }
                                    }
                                } else {
                                    quote! {
                                        ::serde::ser::SerializeMap::serialize_entry(
                                            &mut map, #key, #id
                                        )?;
                                    }
                                }
                            })
                            .collect();
                        quote! {
                            #name::#id { #(#bindings),* } => {
                                #(#entries)*
                            }
                        }
                    }
                    syn::Fields::Unnamed(_) => {
                        quote! {
                            compile_error!("tagged WireEnum tuple variants are not supported — use named fields or unit");
                        }
                    }
                }
            }
        })
        .collect();

    // --- Sibling <Name>Tag unit enum (unit-string WireEnum) ---

    let tag_ident = quote::format_ident!("{}Tag", name);

    let mut tag_variant_tokens: Vec<proc_macro2::TokenStream> = Vec::new();
    for info in &infos {
        let id = &info.ident;
        if info.is_fallback {
            tag_variant_tokens.push(quote! {
                #[doc = "Unknown wire tag — captured for forward compatibility."]
                #[wire_fallback]
                Unknown(::std::string::String)
            });
            continue;
        }
        let VariantWire::Str(primary) = info.wire.as_ref().unwrap() else {
            unreachable!()
        };
        // Primary tag + aliases collapse into ONE tag variant. The unit-string
        // WireEnum derive on the tag enum expands `#[wire_alias = "..."]` into
        // extra `From<&str>` arms pointing at the same variant, so parsers see
        // `Tag::Foo` regardless of whether the wire tag was the primary or an
        // alias.
        let alias_attrs = info.aliases.iter().map(|a| quote! { #[wire_alias = #a] });
        tag_variant_tokens.push(quote! {
            #[wire = #primary]
            #(#alias_attrs)*
            #id
        });
    }

    // --- Final expansion ---

    let discriminator_lit = discriminator;

    quote! {
        impl #name {
            /// The wire tag this variant serializes as — the JSON discriminator
            /// and the exact tag the parser dispatches on.
            pub fn wire_tag(&self) -> &str {
                match self {
                    #(#wire_tag_arms,)*
                }
            }

            /// Back-compat alias of [`Self::wire_tag`].
            #[inline]
            pub fn tag_name(&self) -> &str {
                self.wire_tag()
            }
        }

        impl ::serde::Serialize for #name {
            fn serialize<S: ::serde::Serializer>(
                &self,
                serializer: S,
            ) -> ::core::result::Result<S::Ok, S::Error> {
                use ::serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(None)?;
                ::serde::ser::SerializeMap::serialize_entry(
                    &mut map, #discriminator_lit, self.wire_tag()
                )?;
                match self {
                    #(#serialize_arms,)*
                }
                ::serde::ser::SerializeMap::end(map)
            }
        }

        /// Sibling unit enum listing every canonical wire tag for parser
        /// dispatch. Primary wire tags and any `#[wire_alias]` entries all
        /// resolve to the same variant via `From<&str>`.
        #[doc = "Auto-generated by `#[derive(WireEnum)]`."]
        #[derive(Debug, Clone, PartialEq, Eq, ::wacore::WireEnum)]
        #[allow(clippy::enum_variant_names)]
        pub enum #tag_ident {
            #(#tag_variant_tokens,)*
        }
    }
}
