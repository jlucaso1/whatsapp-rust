use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{
    Data, DataEnum, DataStruct, DeriveInput, Fields, Type, parse_macro_input, spanned::Spanned,
};

#[proc_macro_derive(Reflect)]
pub fn derive_reflect(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    if !input.generics.params.is_empty() {
        return syn::Error::new(
            input.generics.span(),
            "#[derive(Reflect)] does not support generic parameters yet",
        )
        .to_compile_error()
        .into();
    }

    let span = input.span();
    let ident = input.ident;
    let helper_mod = helper_module_ident(&ident);

    let expanded = match input.data {
        Data::Struct(data) => expand_struct(&ident, helper_mod, data),
        Data::Enum(data) => expand_enum(&ident, helper_mod, data),
        Data::Union(_) => syn::Error::new(span, "union types are not supported").to_compile_error(),
    };

    expanded.into()
}

fn expand_struct(
    ident: &syn::Ident,
    helper_mod: syn::Ident,
    data: DataStruct,
) -> proc_macro2::TokenStream {
    let (field_defs, field_entries, struct_style) = build_fields(&data.fields, ident, "field");
    let fields_count = field_entries.len();
    let struct_style_expr = match struct_style {
        StructKind::Named => quote! { ::reflect_metadata::StructStyle::Named },
        StructKind::Tuple => quote! { ::reflect_metadata::StructStyle::Tuple },
        StructKind::Unit => quote! { ::reflect_metadata::StructStyle::Unit },
    };

    quote! {
        mod #helper_mod {
            #![allow(non_upper_case_globals, non_snake_case)]
            use super::*;
            use ::reflect_metadata::{self, FieldDescriptor, StructDescriptor, StructStyle, TypeDescriptor, TypeExpr, TypeKind};

            #(#field_defs)*

            const FIELDS: [FieldDescriptor; #fields_count] = [
                #(#field_entries),*
            ];

            const STRUCT_DESCRIPTOR: StructDescriptor = StructDescriptor {
                fields: &FIELDS,
                style: #struct_style_expr,
            };

            pub const TYPE_DESCRIPTOR: TypeDescriptor = TypeDescriptor {
                name: stringify!(#ident),
                module_path: module_path!(),
                kind: TypeKind::Struct(&STRUCT_DESCRIPTOR),
            };
        }

        impl ::reflect_metadata::Reflect for #ident {
            fn descriptor() -> &'static ::reflect_metadata::TypeDescriptor {
                &#helper_mod::TYPE_DESCRIPTOR
            }
        }
    }
}

fn expand_enum(
    ident: &syn::Ident,
    helper_mod: syn::Ident,
    data: DataEnum,
) -> proc_macro2::TokenStream {
    let mut variant_defs = Vec::new();
    let mut variant_entries = Vec::new();

    for (idx, variant) in data.variants.into_iter().enumerate() {
        let variant_ident = variant.ident;
        let name_str = variant_ident.to_string();
        let prefix = format!("variant{}_{}", idx, name_str);
        let (field_defs, field_entries, struct_style) =
            build_fields(&variant.fields, ident, &prefix);
        let struct_style_expr = match struct_style {
            StructKind::Named => quote! { ::reflect_metadata::StructStyle::Named },
            StructKind::Tuple => quote! { ::reflect_metadata::StructStyle::Tuple },
            StructKind::Unit => quote! { ::reflect_metadata::StructStyle::Unit },
        };
        let fields_len = field_entries.len();
        let fields_const = format_ident!("{}_FIELDS", prefix.to_uppercase());
        let variant_const = format_ident!("{}_DESC", prefix.to_uppercase());

        variant_defs.push(quote! {
            #(#field_defs)*

            const #fields_const: [::reflect_metadata::FieldDescriptor; #fields_len] = [
                #(#field_entries),*
            ];

            const #variant_const: ::reflect_metadata::VariantDescriptor = ::reflect_metadata::VariantDescriptor {
                name: #name_str,
                fields: &#fields_const,
                style: #struct_style_expr,
            };
        });

        variant_entries.push(quote! { #variant_const });
    }

    let variants_len = variant_entries.len();

    quote! {
        mod #helper_mod {
            #![allow(non_upper_case_globals, non_snake_case)]
            use super::*;
            use ::reflect_metadata::{self, EnumDescriptor, FieldDescriptor, StructStyle, TypeDescriptor, TypeKind, VariantDescriptor};

            #(#variant_defs)*

            const VARIANTS: [VariantDescriptor; #variants_len] = [
                #(#variant_entries),*
            ];

            const ENUM_DESCRIPTOR: EnumDescriptor = EnumDescriptor {
                variants: &VARIANTS,
            };

            pub const TYPE_DESCRIPTOR: TypeDescriptor = TypeDescriptor {
                name: stringify!(#ident),
                module_path: module_path!(),
                kind: TypeKind::Enum(&ENUM_DESCRIPTOR),
            };
        }

        impl ::reflect_metadata::Reflect for #ident {
            fn descriptor() -> &'static ::reflect_metadata::TypeDescriptor {
                &#helper_mod::TYPE_DESCRIPTOR
            }
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum StructKind {
    Named,
    Tuple,
    Unit,
}

fn build_fields(
    fields: &Fields,
    type_ident: &syn::Ident,
    prefix: &str,
) -> (
    Vec<proc_macro2::TokenStream>,
    Vec<proc_macro2::TokenStream>,
    StructKind,
) {
    let mut field_defs = Vec::new();
    let mut entries = Vec::new();
    let mut counter = 0usize;
    let type_stem = sanitize_ident_component(&type_ident.to_string());

    match fields {
        Fields::Named(named) => {
            for field in &named.named {
                let field_name = field.ident.as_ref().unwrap().to_string();
                let sanitized = sanitize_ident_component(&field_name);
                let const_ident = format_ident!("__{}_{}_TYPE{}", type_stem, sanitized, counter);
                counter += 1;
                let (defs, expr_ident) = build_type_expr(&field.ty, &const_ident, &mut counter);
                field_defs.extend(defs);
                let entry = quote! {
                    ::reflect_metadata::FieldDescriptor {
                        name: #field_name,
                        ty: &#expr_ident,
                    }
                };
                entries.push(entry);
            }
            (field_defs, entries, StructKind::Named)
        }
        Fields::Unnamed(unnamed) => {
            for (idx, field) in unnamed.unnamed.iter().enumerate() {
                let name = format!("{}_{}_{}", type_ident, prefix, idx);
                let sanitized = sanitize_ident_component(&name);
                let const_ident = format_ident!("__{}_TYPE{}", sanitized, counter);
                counter += 1;
                let (defs, expr_ident) = build_type_expr(&field.ty, &const_ident, &mut counter);
                field_defs.extend(defs);
                let field_name = format!("_{}", idx);
                entries.push(quote! {
                    ::reflect_metadata::FieldDescriptor {
                        name: #field_name,
                        ty: &#expr_ident,
                    }
                });
            }
            (field_defs, entries, StructKind::Tuple)
        }
        Fields::Unit => (field_defs, entries, StructKind::Unit),
    }
}

fn helper_module_ident(type_ident: &syn::Ident) -> syn::Ident {
    let raw = type_ident.to_string();
    let mut output = String::from("__reflect_");
    let mut last_was_underscore = false;
    let mut seen_char = false;

    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            if ch.is_ascii_uppercase() {
                if seen_char && !last_was_underscore {
                    output.push('_');
                }
                output.push(ch.to_ascii_lowercase());
                last_was_underscore = false;
            } else {
                output.push(ch);
                last_was_underscore = false;
            }
            seen_char = true;
        } else if !last_was_underscore {
            output.push('_');
            last_was_underscore = true;
            seen_char = true;
        }
    }

    if output.ends_with('_') {
        output.pop();
    }
    if output == "__reflect_" {
        output.push('t');
    }

    format_ident!("{}", output)
}

fn sanitize_ident_component(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            output.push(ch.to_ascii_uppercase());
        } else {
            output.push('_');
        }
    }
    if output.is_empty() {
        output.push('_');
    }
    if output
        .as_bytes()
        .first()
        .map(|b| b.is_ascii_digit())
        .unwrap_or(false)
    {
        output.insert(0, '_');
    }
    output
}

fn build_type_expr(
    ty: &Type,
    stem: &syn::Ident,
    counter: &mut usize,
) -> (Vec<proc_macro2::TokenStream>, proc_macro2::Ident) {
    let mut defs = Vec::new();

    let result_ident = match ty {
        Type::Path(path) => {
            let last = path.path.segments.last().unwrap();
            let ident_str = last.ident.to_string();
            match ident_str.as_str() {
                "String" => {
                    let ident = format_ident!("{}_PRIM_{}", stem, counter);
                    *counter += 1;
                    defs.push(quote! {
                        const #ident: ::reflect_metadata::TypeExpr = ::reflect_metadata::TypeExpr::Primitive(::reflect_metadata::PrimitiveType::String);
                    });
                    ident
                }
                "bool" => primitive_expr(
                    stem,
                    counter,
                    &mut defs,
                    quote! { ::reflect_metadata::PrimitiveType::Bool },
                ),
                "i8" => primitive_expr(
                    stem,
                    counter,
                    &mut defs,
                    quote! { ::reflect_metadata::PrimitiveType::I8 },
                ),
                "i16" => primitive_expr(
                    stem,
                    counter,
                    &mut defs,
                    quote! { ::reflect_metadata::PrimitiveType::I16 },
                ),
                "i32" => primitive_expr(
                    stem,
                    counter,
                    &mut defs,
                    quote! { ::reflect_metadata::PrimitiveType::I32 },
                ),
                "i64" => primitive_expr(
                    stem,
                    counter,
                    &mut defs,
                    quote! { ::reflect_metadata::PrimitiveType::I64 },
                ),
                "u8" => primitive_expr(
                    stem,
                    counter,
                    &mut defs,
                    quote! { ::reflect_metadata::PrimitiveType::U8 },
                ),
                "u16" => primitive_expr(
                    stem,
                    counter,
                    &mut defs,
                    quote! { ::reflect_metadata::PrimitiveType::U16 },
                ),
                "u32" => primitive_expr(
                    stem,
                    counter,
                    &mut defs,
                    quote! { ::reflect_metadata::PrimitiveType::U32 },
                ),
                "u64" => primitive_expr(
                    stem,
                    counter,
                    &mut defs,
                    quote! { ::reflect_metadata::PrimitiveType::U64 },
                ),
                "f32" => primitive_expr(
                    stem,
                    counter,
                    &mut defs,
                    quote! { ::reflect_metadata::PrimitiveType::F32 },
                ),
                "f64" => primitive_expr(
                    stem,
                    counter,
                    &mut defs,
                    quote! { ::reflect_metadata::PrimitiveType::F64 },
                ),
                "Vec" => match &last.arguments {
                    syn::PathArguments::AngleBracketed(args) => {
                        if let Some(inner_ty) = args.args.first() {
                            if let syn::GenericArgument::Type(inner_type) = inner_ty {
                                let inner_stem = format_ident!("{}_SEQ_INNER{}", stem, counter);
                                *counter += 1;
                                let (inner_defs, inner_ident) =
                                    build_type_expr(inner_type, &inner_stem, counter);
                                defs.extend(inner_defs);
                                let ident = format_ident!("{}_SEQ_{}", stem, counter);
                                *counter += 1;
                                defs.push(quote! {
                                        const #ident: ::reflect_metadata::TypeExpr = ::reflect_metadata::TypeExpr::Sequence(&#inner_ident);
                                    });
                                ident
                            } else {
                                opaque_expr(ty, stem, counter, &mut defs)
                            }
                        } else {
                            opaque_expr(ty, stem, counter, &mut defs)
                        }
                    }
                    _ => opaque_expr(ty, stem, counter, &mut defs),
                },
                "Option" => match &last.arguments {
                    syn::PathArguments::AngleBracketed(args) => {
                        if let Some(inner_ty) = args.args.first() {
                            if let syn::GenericArgument::Type(inner_type) = inner_ty {
                                let inner_stem = format_ident!("{}_OPT_INNER{}", stem, counter);
                                *counter += 1;
                                let (inner_defs, inner_ident) =
                                    build_type_expr(inner_type, &inner_stem, counter);
                                defs.extend(inner_defs);
                                let ident = format_ident!("{}_OPT_{}", stem, counter);
                                *counter += 1;
                                defs.push(quote! {
                                        const #ident: ::reflect_metadata::TypeExpr = ::reflect_metadata::TypeExpr::Optional(&#inner_ident);
                                    });
                                ident
                            } else {
                                opaque_expr(ty, stem, counter, &mut defs)
                            }
                        } else {
                            opaque_expr(ty, stem, counter, &mut defs)
                        }
                    }
                    _ => opaque_expr(ty, stem, counter, &mut defs),
                },
                "HashMap" | "BTreeMap" => match &last.arguments {
                    syn::PathArguments::AngleBracketed(args) => {
                        let mut args_iter = args.args.iter();
                        if let (Some(first), Some(second)) = (args_iter.next(), args_iter.next()) {
                            if let (
                                syn::GenericArgument::Type(key_ty),
                                syn::GenericArgument::Type(value_ty),
                            ) = (first, second)
                            {
                                let key_stem = format_ident!("{}_MAP_KEY{}", stem, counter);
                                *counter += 1;
                                let (key_defs, key_ident) =
                                    build_type_expr(key_ty, &key_stem, counter);
                                defs.extend(key_defs);
                                let value_stem = format_ident!("{}_MAP_VALUE{}", stem, counter);
                                *counter += 1;
                                let (value_defs, value_ident) =
                                    build_type_expr(value_ty, &value_stem, counter);
                                defs.extend(value_defs);
                                let ident = format_ident!("{}_MAP_{}", stem, counter);
                                *counter += 1;
                                defs.push(quote! {
                                        const #ident: ::reflect_metadata::TypeExpr = ::reflect_metadata::TypeExpr::Map {
                                            key: &#key_ident,
                                            value: &#value_ident,
                                        };
                                    });
                                ident
                            } else {
                                opaque_expr(ty, stem, counter, &mut defs)
                            }
                        } else {
                            opaque_expr(ty, stem, counter, &mut defs)
                        }
                    }
                    _ => opaque_expr(ty, stem, counter, &mut defs),
                },
                _other => {
                    let path_string = quote!(#path).to_string();
                    let ident = format_ident!("{}_NAMED_{}", stem, counter);
                    *counter += 1;
                    defs.push(quote! {
                        const #ident: ::reflect_metadata::TypeExpr = ::reflect_metadata::TypeExpr::Named(#path_string);
                    });
                    ident
                }
            }
        }
        Type::Reference(reference) => {
            let inner_stem = format_ident!("{}_REF_INNER{}", stem, counter);
            *counter += 1;
            let (inner_defs, inner_ident) = build_type_expr(&reference.elem, &inner_stem, counter);
            defs.extend(inner_defs);
            inner_ident
        }
        Type::Tuple(tuple) => {
            let mut inner_idents = Vec::new();
            for (idx, elem) in tuple.elems.iter().enumerate() {
                let inner_stem = format_ident!("{}_TUP{}_{}", stem, counter, idx);
                *counter += 1;
                let (inner_defs, inner_ident) = build_type_expr(elem, &inner_stem, counter);
                defs.extend(inner_defs);
                inner_idents.push(inner_ident);
            }
            let tuple_len = inner_idents.len();
            let array_ident = format_ident!("{}_TUP_ARR{}", stem, counter);
            *counter += 1;
            let tuple_ident = format_ident!("{}_TUP_{}", stem, counter);
            *counter += 1;
            let refs = inner_idents.iter().map(|ident| quote! { &#ident });
            defs.push(quote! {
                const #array_ident: [&'static ::reflect_metadata::TypeExpr; #tuple_len] = [
                    #( #refs ),*
                ];
            });
            defs.push(quote! {
                const #tuple_ident: ::reflect_metadata::TypeExpr = ::reflect_metadata::TypeExpr::Tuple(&#array_ident);
            });
            tuple_ident
        }
        _ => opaque_expr(ty, stem, counter, &mut defs),
    };

    (defs, result_ident)
}

fn primitive_expr(
    stem: &syn::Ident,
    counter: &mut usize,
    defs: &mut Vec<proc_macro2::TokenStream>,
    variant: proc_macro2::TokenStream,
) -> proc_macro2::Ident {
    let ident = format_ident!("{}_PRIM_{}", stem, counter);
    *counter += 1;
    defs.push(quote! {
        const #ident: ::reflect_metadata::TypeExpr = ::reflect_metadata::TypeExpr::Primitive(#variant);
    });
    ident
}

fn opaque_expr(
    ty: &Type,
    stem: &syn::Ident,
    counter: &mut usize,
    defs: &mut Vec<proc_macro2::TokenStream>,
) -> proc_macro2::Ident {
    let ident = format_ident!("{}_OPAQUE_{}", stem, counter);
    *counter += 1;
    let ty_str = quote!(#ty).to_string();
    defs.push(quote! {
        const #ident: ::reflect_metadata::TypeExpr = ::reflect_metadata::TypeExpr::Opaque(#ty_str);
    });
    ident
}
