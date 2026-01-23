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
/// - `#[attr(name = "attrname")]` - Marks a field as an XML attribute.
/// - `#[attr(name = "attrname", default = "value")]` - Attribute with default value.
///
/// # Example
///
/// ```ignore
/// #[derive(ProtocolNode)]
/// #[protocol(tag = "query")]
/// pub struct QueryRequest {
///     #[attr(name = "request", default = "interactive")]
///     pub request_type: String,
/// }
/// ```
#[proc_macro_derive(ProtocolNode, attributes(protocol, attr))]
pub fn derive_protocol_node(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = &input.ident;

    // Extract tag from #[protocol(tag = "...")]
    let tag = match extract_tag(&input.attrs) {
        Some(tag) => tag,
        None => {
            return syn::Error::new_spanned(
                &input.ident,
                "ProtocolNode requires #[protocol(tag = \"...\")]",
            )
            .to_compile_error()
            .into();
        }
    };

    // Get fields for struct
    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            Fields::Unit => {
                // Unit struct - no fields
                return generate_empty_impl(name, &tag).into();
            }
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

    // Collect field info
    let mut attr_fields = Vec::new();
    for field in fields {
        if let Some(attr_info) = extract_attr_info(field) {
            attr_fields.push(attr_info);
        }
    }

    // Generate into_node() body
    let attr_setters: Vec<_> = attr_fields
        .iter()
        .map(|info| {
            let field_ident = &info.field_ident;
            let attr_name = &info.attr_name;
            quote! {
                .attr(#attr_name, self.#field_ident.to_string())
            }
        })
        .collect();

    // Generate try_from_node() body
    let field_parsers: Vec<_> = attr_fields
        .iter()
        .map(|info| {
            let field_ident = &info.field_ident;
            let attr_name = &info.attr_name;
            if let Some(default) = &info.default {
                quote! {
                    #field_ident: node.attrs().optional_string(#attr_name)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| #default.to_string())
                }
            } else {
                quote! {
                    #field_ident: node.attrs().optional_string(#attr_name)
                        .ok_or_else(|| ::anyhow::anyhow!("missing required attribute '{}'", #attr_name))?
                        .to_string()
                }
            }
        })
        .collect();

    // Generate Default impl field initializers
    let default_fields: Vec<_> = attr_fields
        .iter()
        .map(|info| {
            let field_ident = &info.field_ident;
            if let Some(default) = &info.default {
                quote! { #field_ident: #default.to_string() }
            } else {
                quote! { #field_ident: String::new() }
            }
        })
        .collect();

    let expanded = quote! {
        impl ::wacore::protocol::ProtocolNode for #name {
            fn tag(&self) -> &'static str {
                #tag
            }

            fn into_node(self) -> ::wacore_binary::node::Node {
                ::wacore_binary::builder::NodeBuilder::new(#tag)
                    #(#attr_setters)*
                    .build()
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

        impl ::core::default::Default for #name {
            fn default() -> Self {
                Self {
                    #(#default_fields),*
                }
            }
        }
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

    // Extract tag from #[protocol(tag = "...")]
    let tag = match extract_tag(&input.attrs) {
        Some(tag) => tag,
        None => {
            return syn::Error::new_spanned(
                &input.ident,
                "EmptyNode requires #[protocol(tag = \"...\")]",
            )
            .to_compile_error()
            .into();
        }
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

struct AttrFieldInfo {
    field_ident: syn::Ident,
    attr_name: String,
    default: Option<String>,
}

fn extract_tag(attrs: &[syn::Attribute]) -> Option<String> {
    for attr in attrs {
        if attr.path().is_ident("protocol") {
            let mut tag = None;
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("tag") {
                    let value: syn::LitStr = meta.value()?.parse()?;
                    tag = Some(value.value());
                }
                Ok(())
            });
            if tag.is_some() {
                return tag;
            }
        }
    }
    None
}

fn extract_attr_info(field: &syn::Field) -> Option<AttrFieldInfo> {
    let field_ident = field.ident.clone()?;

    for attr in &field.attrs {
        if attr.path().is_ident("attr") {
            // Parse the attribute arguments
            let mut attr_name = None;
            let mut default = None;

            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("name") {
                    let value: syn::LitStr = meta.value()?.parse()?;
                    attr_name = Some(value.value());
                } else if meta.path.is_ident("default") {
                    let value: syn::LitStr = meta.value()?.parse()?;
                    default = Some(value.value());
                }
                Ok(())
            });

            if let Some(name) = attr_name {
                return Some(AttrFieldInfo {
                    field_ident,
                    attr_name: name,
                    default,
                });
            }
        }
    }
    None
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

    for variant in variants {
        let variant_ident = &variant.ident;
        let mut str_value = None;
        let mut is_default = false;

        for attr in &variant.attrs {
            if attr.path().is_ident("str") {
                // Parse #[str = "value"]
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

        if is_default {
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
