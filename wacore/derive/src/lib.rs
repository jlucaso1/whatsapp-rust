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

    let mut attr_fields = Vec::new();
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
                    // Option<Jid> - only insert if Some
                    quote! {
                        if let Some(jid) = self.#field_ident {
                            builder = builder.jid_attr(#attr_name, jid);
                        }
                    }
                }
                (AttrType::Jid, false) => {
                    // Required Jid - always insert
                    quote! {
                        builder = builder.jid_attr(#attr_name, self.#field_ident);
                    }
                }
                (AttrType::String, true) => {
                    // Option<String> - only insert if Some
                    quote! {
                        if let Some(s) = self.#field_ident {
                            builder = builder.attr(#attr_name, s);
                        }
                    }
                }
                (AttrType::String, false) => {
                    // Required String - always insert
                    quote! {
                        builder = builder.attr(#attr_name, self.#field_ident);
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
                    // Required Jid
                    quote! {
                        #field_ident: node.attrs().optional_jid(#attr_name)
                            .ok_or_else(|| ::anyhow::anyhow!("missing required attribute '{}'", #attr_name))?
                    }
                }
                (AttrType::Jid, true, _) => {
                    // Optional Jid
                    quote! {
                        #field_ident: node.attrs().optional_jid(#attr_name)
                    }
                }
                (AttrType::String, false, Some(default)) => {
                    // String with default
                    quote! {
                        #field_ident: node.attrs().optional_string(#attr_name)
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| #default.to_string())
                    }
                }
                (AttrType::String, false, None) => {
                    // Required String
                    quote! {
                        #field_ident: node.attrs().required_string(#attr_name)?.to_string()
                    }
                }
                (AttrType::String, true, Some(default)) => {
                    // Optional String with default (always Some)
                    quote! {
                        #field_ident: node.attrs().optional_string(#attr_name)
                            .map(|s| s.to_string())
                            .or_else(|| Some(#default.to_string()))
                    }
                }
                (AttrType::String, true, None) => {
                    // Optional String
                    quote! {
                        #field_ident: node.attrs().optional_string(#attr_name).map(|s| s.to_string())
                    }
                }
            }
        })
        .collect();

    // Only generate Default impl if all fields have defaults or are optional
    let all_have_defaults = attr_fields
        .iter()
        .all(|info| info.default.is_some() || info.optional);

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

            fn try_from_node(node: &::wacore_binary::node::Node) -> ::anyhow::Result<Self> {
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

            fn try_from_node(node: &::wacore_binary::node::Node) -> ::anyhow::Result<Self> {
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
                } else if meta.path.is_ident("optional") {
                    explicit_optional = true;
                }
                Ok(())
            })?;

            match attr_name {
                Some(name) => {
                    let attr_type = if is_jid {
                        AttrType::Jid
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
/// - `as_str(&self) -> &'static str`
/// - `std::fmt::Display`
/// - `TryFrom<&str>`
/// - `Default` (first variant is default, or use `#[string_default]`)
///
/// # Attributes
///
/// - `#[str = "value"]` - Required on each variant. The string representation.
/// - `#[string_default]` - Optional. Marks this variant as the default.
///
/// # Example
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
#[proc_macro_derive(StringEnum, attributes(str, string_default))]
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

    let mut variant_infos = Vec::new();
    let mut default_variant = None;
    let mut seen_str_values: std::collections::HashMap<String, syn::Ident> =
        std::collections::HashMap::new();

    for variant in variants {
        let variant_ident = &variant.ident;

        if !matches!(variant.fields, syn::Fields::Unit) {
            return syn::Error::new_spanned(
                variant_ident,
                "StringEnum only supports unit variants",
            )
            .to_compile_error()
            .into();
        }

        let mut str_value = None;
        let mut is_default = false;

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
            }
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

    // Check for empty enums
    if variant_infos.is_empty() {
        return syn::Error::new_spanned(
            &input.ident,
            "StringEnum cannot be derived for empty enums",
        )
        .to_compile_error()
        .into();
    }

    // If no explicit default, use first variant
    let default_variant = default_variant.unwrap_or_else(|| variant_infos[0].0.clone());

    // Generate as_str() match arms
    let as_str_arms: Vec<_> = variant_infos
        .iter()
        .map(|(ident, str_val)| {
            quote! { #name::#ident => #str_val }
        })
        .collect();

    // Generate TryFrom match arms
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

        impl ::core::default::Default for #name {
            fn default() -> Self {
                #name::#default_variant
            }
        }
    };

    expanded.into()
}
