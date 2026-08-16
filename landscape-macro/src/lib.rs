use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, DeriveInput, Lit};

/// `#[derive(LdApiError)]` — auto-generate `LdApiErrorInfo` implementation for enums.
///
/// Each variant requires `#[api_error(id = "xxx", status = NNN)]` annotation,
/// except transparent delegate variants (see below).
///
/// Optional variant flag `serialize`: for single-field tuple variants holding a
/// `Box<Details>` (where `Details: Serialize`), `error_args()` serializes the
/// inner struct directly instead of producing `{"0": v0.to_string()}`. Useful to
/// keep a stable named-key JSON shape while keeping the `Result` small.
///
/// Optional variant flag `transparent`: for single-field `#[from]` variants
/// wrapping an error that itself implements `LdApiErrorInfo` (e.g.
/// `Internal(#[from] DbError)`). `error_id()`, `http_status_code()`,
/// `error_args()` and `to_public_message()` all delegate to the wrapped error
/// via method-call resolution (so an inherent `to_public_message` on the inner
/// type, like `DbError`'s redaction, is honored), keeping e.g.
/// `DbError::Conflict`'s `config.conflict`/409 semantics even when nested
/// inside a domain error.
///
/// Example:
/// ```ignore
/// #[derive(thiserror::Error, Debug, LdApiError)]
/// pub enum DnsRuleError {
///     #[error("DNS rule '{0}' not found")]
///     #[api_error(id = "dns_rule.not_found", status = 404)]
///     NotFound(ConfigId),
/// }
/// ```
#[proc_macro_derive(LdApiError, attributes(api_error))]
pub fn derive_ld_api_error(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    // Check for enum-level #[api_error(crate_path = "...")] to override the default crate path.
    // Use `crate` when the derive is used within landscape-common itself.
    let mut crate_path_str = "landscape_common".to_string();
    for attr in &input.attrs {
        if attr.path().is_ident("api_error") {
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("crate_path") {
                    let value = meta.value()?;
                    let lit: Lit = value.parse()?;
                    if let Lit::Str(s) = lit {
                        crate_path_str = s.value();
                    }
                }
                Ok(())
            });
        }
    }
    let crate_path: syn::Path = syn::parse_str(&crate_path_str).unwrap();

    let variants = match &input.data {
        syn::Data::Enum(data) => &data.variants,
        _ => panic!("LdApiError only supports enums"),
    };

    let mut id_arms = vec![];
    let mut status_arms = vec![];
    let mut args_arms = vec![];
    let mut to_public_arms = vec![];

    for variant in variants {
        let variant_ident = &variant.ident;

        // Parse #[api_error(id = "...", status = NNN, serialize, transparent)]
        let api_error_attr =
            variant.attrs.iter().find(|a| a.path().is_ident("api_error")).unwrap_or_else(|| {
                panic!(
                    "Variant `{}` is missing #[api_error(id = \"...\", status = NNN)] attribute",
                    variant_ident
                )
            });

        let mut error_id: Option<String> = None;
        let mut status_code: Option<u16> = None;
        let mut serialize: bool = false;
        let mut transparent: bool = false;

        api_error_attr
            .parse_nested_meta(|meta| {
                if meta.path.is_ident("id") {
                    let value = meta.value()?;
                    let lit: Lit = value.parse()?;
                    if let Lit::Str(s) = lit {
                        error_id = Some(s.value());
                    }
                } else if meta.path.is_ident("status") {
                    let value = meta.value()?;
                    let lit: Lit = value.parse()?;
                    if let Lit::Int(i) = lit {
                        status_code = Some(i.base10_parse().unwrap());
                    }
                } else if meta.path.is_ident("serialize") {
                    serialize = true;
                } else if meta.path.is_ident("transparent") {
                    transparent = true;
                }
                Ok(())
            })
            .unwrap_or_else(|e| {
                panic!("Failed to parse #[api_error] on variant `{}`: {}", variant_ident, e)
            });

        // Transparent delegate variant: single #[from] field wrapping an error
        // that implements LdApiErrorInfo. All API metadata is delegated.
        let delegate_pat = if transparent {
            let field = match &variant.fields {
                syn::Fields::Unnamed(f) if f.unnamed.len() == 1 => &f.unnamed[0],
                _ => panic!(
                    "`transparent` variant `{}` must have exactly one unnamed field",
                    variant_ident
                ),
            };
            let is_from = field.attrs.iter().any(|a| a.path().is_ident("from"));
            if !is_from {
                panic!("`transparent` variant `{}` field must be marked #[from]", variant_ident);
            }
            Some(quote! { Self::#variant_ident(v0) })
        } else {
            let error_id = error_id
                .unwrap_or_else(|| panic!("Missing `id` in #[api_error] on `{}`", variant_ident));
            let status_code = status_code.unwrap_or_else(|| {
                panic!("Missing `status` in #[api_error] on `{}`", variant_ident)
            });

            // Build wildcard match pattern for id/status arms
            let pattern = match &variant.fields {
                syn::Fields::Unit => quote! { Self::#variant_ident },
                syn::Fields::Unnamed(_) => quote! { Self::#variant_ident(..) },
                syn::Fields::Named(_) => quote! { Self::#variant_ident { .. } },
            };

            id_arms.push(quote! { #pattern => #error_id });
            status_arms.push(quote! { #pattern => #status_code });

            // Build error_args() arm with field bindings
            let args_arm = match &variant.fields {
                syn::Fields::Unit => {
                    quote! { Self::#variant_ident => serde_json::json!({}) }
                }
                syn::Fields::Unnamed(fields) => {
                    // Check if any field has #[from] attribute
                    let has_from = fields
                        .unnamed
                        .iter()
                        .any(|f| f.attrs.iter().any(|a| a.path().is_ident("from")));
                    if has_from {
                        quote! { Self::#variant_ident(..) => serde_json::json!({}) }
                    } else if serialize && fields.unnamed.len() == 1 {
                        // 单字段 Box<Details> 变体：直接序列化 Details 结构体作为 error_args
                        quote! {
                            Self::#variant_ident(v0) => {
                                serde_json::to_value(v0).unwrap_or_else(|_| serde_json::json!({}))
                            }
                        }
                    } else {
                        let bindings: Vec<_> = fields
                            .unnamed
                            .iter()
                            .enumerate()
                            .map(|(i, _)| format_ident!("v{}", i))
                            .collect();
                        let entries: Vec<_> = bindings
                            .iter()
                            .enumerate()
                            .map(|(i, ident)| {
                                let key = i.to_string();
                                quote! { #key: #ident.to_string() }
                            })
                            .collect();
                        quote! {
                            Self::#variant_ident(#(#bindings),*) => serde_json::json!({ #(#entries),* })
                        }
                    }
                }
                syn::Fields::Named(fields) => {
                    // Check if any field has #[from] attribute
                    let has_from = fields
                        .named
                        .iter()
                        .any(|f| f.attrs.iter().any(|a| a.path().is_ident("from")));
                    if has_from {
                        quote! { Self::#variant_ident { .. } => serde_json::json!({}) }
                    } else {
                        let field_names: Vec<_> =
                            fields.named.iter().map(|f| f.ident.as_ref().unwrap()).collect();
                        let entries: Vec<_> = field_names
                            .iter()
                            .map(|ident| {
                                let key = ident.to_string();
                                quote! { #key: #ident }
                            })
                            .collect();
                        quote! {
                            Self::#variant_ident { #(#field_names),* } => serde_json::json!({ #(#entries),* })
                        }
                    }
                }
            };
            args_arms.push(args_arm);

            None
        };

        if let Some(pat) = &delegate_pat {
            id_arms.push(quote! { #pat => v0.error_id() });
            status_arms.push(quote! { #pat => v0.http_status_code() });
            args_arms.push(quote! { #pat => v0.error_args() });
            to_public_arms.push(quote! { #pat => v0.to_public_message() });
        }
    }

    // Method-call delegation: inherent methods win over trait methods, so e.g.
    // `DbError`'s inherent `to_public_message` redaction is honored when wrapped
    // by a transparent variant. `use ... as _` brings the trait into scope for
    // wrapped errors that only implement `LdApiErrorInfo`.
    let use_trait = if to_public_arms.is_empty() {
        quote! {}
    } else {
        quote! { use #crate_path::error::LdApiErrorInfo as _; }
    };

    let to_public_impl = if to_public_arms.is_empty() {
        quote! {}
    } else {
        quote! {
            fn to_public_message(&self) -> String {
                match self {
                    #( #to_public_arms, )*
                    _ => self.to_string(),
                }
            }
        }
    };

    let expanded = quote! {
        impl #crate_path::error::LdApiErrorInfo for #name {
            fn error_id(&self) -> &'static str {
                #use_trait
                match self {
                    #( #id_arms, )*
                }
            }

            fn http_status_code(&self) -> u16 {
                #use_trait
                match self {
                    #( #status_arms, )*
                }
            }

            fn error_args(&self) -> serde_json::Value {
                #use_trait
                match self {
                    #( #args_arms, )*
                }
            }

            #to_public_impl
        }
    };

    expanded.into()
}
