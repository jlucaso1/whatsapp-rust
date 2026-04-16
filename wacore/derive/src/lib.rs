//! Derive macros for wacore protocol types.
//!
//! This crate provides derive macros for implementing the `ProtocolNode` trait
//! on structs that represent WhatsApp protocol nodes.
//!
//! # Example
//!
//! ```ignore
//! use wacore_derive::{ProtocolNode, StringEnum};
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
//! #[derive(StringEnum)]
//! pub enum MemberAddMode {
//!     #[str = "admin_add"]
//!     AdminAdd,
//!     #[str = "all_member_add"]
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
/// - `#[attr(name = "attrname", string_enum)]` - Marks a StringEnum field (uses `as_str()`/`TryFrom`).
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

/// Derive macro for enums with string representations.
///
/// Automatically implements:
/// - `as_str(&self) -> &'static str` (or `&str` with fallback)
/// - `std::fmt::Display`
/// - `TryFrom<&str>` (or `From<&str>` with fallback)
/// - `Default` (first variant is default, or use `#[string_default]`)
///
/// # Attributes
///
/// - `#[str = "value"]` - Required on each unit variant. The string representation.
/// - `#[string_default]` - Optional. Marks this variant as the default.
/// - `#[string_fallback]` - Optional. Marks a `VariantName(String)` variant as catch-all.
///   When present, unknown strings are captured instead of returning an error.
///   Generates `From<&str>` instead of `TryFrom<&str>`, and `as_str()` returns `&str`.
///
/// # Example (standard)
///
/// ```ignore
/// #[derive(StringEnum)]
/// pub enum MemberAddMode {
///     #[str = "admin_add"]
///     AdminAdd,
///     #[string_default]
///     #[str = "all_member_add"]
///     AllMemberAdd,
/// }
///
/// assert_eq!(MemberAddMode::AdminAdd.as_str(), "admin_add");
/// assert_eq!(MemberAddMode::try_from("all_member_add").unwrap(), MemberAddMode::AllMemberAdd);
/// ```
///
/// # Example (with fallback)
///
/// ```ignore
/// #[derive(StringEnum)]
/// pub enum PrivacyCategory {
///     #[str = "last"]
///     Last,
///     #[str = "online"]
///     Online,
///     #[string_fallback]
///     Other(String),
/// }
///
/// assert_eq!(PrivacyCategory::Last.as_str(), "last");
/// assert_eq!(PrivacyCategory::from("last"), PrivacyCategory::Last);
/// assert_eq!(PrivacyCategory::from("unknown"), PrivacyCategory::Other("unknown".to_string()));
/// ```
#[proc_macro_derive(StringEnum, attributes(str, string_default, string_fallback))]
pub fn derive_string_enum(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = &input.ident;

    let variants = match &input.data {
        Data::Enum(data) => &data.variants,
        _ => {
            return syn::Error::new_spanned(
                &input.ident,
                "StringEnum can only be derived for enums",
            )
            .to_compile_error()
            .into();
        }
    };

    let mut variant_infos = Vec::with_capacity(variants.len());
    let mut default_variant = None;
    let mut fallback_variant: Option<syn::Ident> = None;
    let mut seen_str_values: std::collections::HashMap<String, syn::Ident> =
        std::collections::HashMap::new();

    for variant in variants {
        let variant_ident = &variant.ident;

        let mut is_default = false;
        let mut is_fallback = false;
        let mut str_value = None;

        for attr in &variant.attrs {
            if attr.path().is_ident("str") {
                if let syn::Meta::NameValue(nv) = &attr.meta
                    && let syn::Expr::Lit(expr_lit) = &nv.value
                    && let syn::Lit::Str(lit_str) = &expr_lit.lit
                {
                    str_value = Some(lit_str.value());
                }
            } else if attr.path().is_ident("string_default") {
                is_default = true;
            } else if attr.path().is_ident("string_fallback") {
                is_fallback = true;
            }
        }

        if is_fallback {
            // Validate: fallback variant must have exactly one unnamed String field
            match &variant.fields {
                syn::Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {}
                _ => {
                    return syn::Error::new_spanned(
                        variant_ident,
                        "string_fallback variant must have exactly one unnamed field: VariantName(String)",
                    )
                    .to_compile_error()
                    .into();
                }
            }
            if fallback_variant.is_some() {
                return syn::Error::new_spanned(
                    variant_ident,
                    "Multiple #[string_fallback] attributes found; only one variant may be the fallback",
                )
                .to_compile_error()
                .into();
            }
            if str_value.is_some() {
                return syn::Error::new_spanned(
                    variant_ident,
                    "string_fallback variant should not have a #[str = \"...\"] attribute",
                )
                .to_compile_error()
                .into();
            }
            fallback_variant = Some(variant_ident.clone());

            if is_default {
                if default_variant.is_some() {
                    return syn::Error::new_spanned(
                        variant_ident,
                        "Multiple #[string_default] attributes found; only one variant may be the default",
                    )
                    .to_compile_error()
                    .into();
                }
                default_variant = Some(variant_ident.clone());
            }
            continue;
        }

        // Non-fallback variant must be a unit variant
        if !matches!(variant.fields, syn::Fields::Unit) {
            return syn::Error::new_spanned(
                variant_ident,
                "StringEnum only supports unit variants (except the #[string_fallback] variant)",
            )
            .to_compile_error()
            .into();
        }

        let str_val = match str_value {
            Some(v) => v,
            None => {
                return syn::Error::new_spanned(
                    variant_ident,
                    format!(
                        "StringEnum variant {} requires #[str = \"...\"] attribute",
                        variant_ident
                    ),
                )
                .to_compile_error()
                .into();
            }
        };

        if let Some(prev_variant) = seen_str_values.get(&str_val) {
            return syn::Error::new_spanned(
                variant_ident,
                format!(
                    "duplicate #[str = \"{}\"] value; already used by variant `{}`",
                    str_val, prev_variant
                ),
            )
            .to_compile_error()
            .into();
        }
        seen_str_values.insert(str_val.clone(), variant_ident.clone());

        if is_default {
            if default_variant.is_some() {
                return syn::Error::new_spanned(
                    variant_ident,
                    "Multiple #[string_default] attributes found; only one variant may be the default",
                )
                .to_compile_error()
                .into();
            }
            default_variant = Some(variant_ident.clone());
        }

        variant_infos.push((variant_ident.clone(), str_val));
    }

    // Check for empty enums (must have at least one known variant or a fallback)
    if variant_infos.is_empty() && fallback_variant.is_none() {
        return syn::Error::new_spanned(
            &input.ident,
            "StringEnum cannot be derived for empty enums",
        )
        .to_compile_error()
        .into();
    }

    // If no explicit default, use first variant
    let default_variant = default_variant.unwrap_or_else(|| variant_infos[0].0.clone());

    if let Some(ref fallback_ident) = fallback_variant {
        // === Fallback mode: as_str() returns &str, From<&str> instead of TryFrom ===

        let as_str_arms: Vec<_> = variant_infos
            .iter()
            .map(|(ident, str_val)| {
                quote! { #name::#ident => #str_val }
            })
            .collect();

        let from_arms: Vec<_> = variant_infos
            .iter()
            .map(|(ident, str_val)| {
                quote! { #str_val => #name::#ident }
            })
            .collect();

        let expanded = quote! {
            impl #name {
                /// Returns the string representation of this enum variant.
                pub fn as_str(&self) -> &str {
                    match self {
                        #(#as_str_arms,)*
                        #name::#fallback_ident(s) => s.as_str(),
                    }
                }
            }

            impl ::core::fmt::Display for #name {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    f.write_str(self.as_str())
                }
            }

            impl ::core::convert::From<&str> for #name {
                fn from(value: &str) -> Self {
                    match value {
                        #(#from_arms,)*
                        other => #name::#fallback_ident(other.to_string()),
                    }
                }
            }

            impl ::wacore::protocol::ParseStringEnum for #name {
                fn parse_from_str(s: &str) -> ::anyhow::Result<Self> {
                    Ok(::core::convert::From::from(s))
                }
            }

            impl ::core::default::Default for #name {
                fn default() -> Self {
                    #name::#default_variant
                }
            }
        };

        expanded.into()
    } else {
        // === Standard mode: as_str() returns &'static str, TryFrom<&str> ===

        let as_str_arms: Vec<_> = variant_infos
            .iter()
            .map(|(ident, str_val)| {
                quote! { #name::#ident => #str_val }
            })
            .collect();

        let try_from_arms: Vec<_> = variant_infos
            .iter()
            .map(|(ident, str_val)| {
                quote! { #str_val => Ok(#name::#ident) }
            })
            .collect();

        let expanded = quote! {
            impl #name {
                /// Returns the string representation of this enum variant.
                pub fn as_str(&self) -> &'static str {
                    match self {
                        #(#as_str_arms),*
                    }
                }
            }

            impl ::core::fmt::Display for #name {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    f.write_str(self.as_str())
                }
            }

            impl ::core::convert::TryFrom<&str> for #name {
                type Error = ::anyhow::Error;

                fn try_from(value: &str) -> ::core::result::Result<Self, Self::Error> {
                    match value {
                        #(#try_from_arms),*,
                        _ => Err(::anyhow::anyhow!("unknown {}: {}", stringify!(#name), value)),
                    }
                }
            }

            impl ::wacore::protocol::ParseStringEnum for #name {
                fn parse_from_str(s: &str) -> ::anyhow::Result<Self> {
                    ::core::convert::TryFrom::try_from(s)
                }
            }

            impl ::core::default::Default for #name {
                fn default() -> Self {
                    #name::#default_variant
                }
            }
        };

        expanded.into()
    }
}
