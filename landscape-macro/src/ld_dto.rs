//! DTO derives for landscape config structs: `LdCreate`, `LdUpdate`, `LdView`.
//!
//! A config struct doubles as the API wire type today; these derives split
//! that contract at the type level, per macro, on demand:
//!
//! - `LdCreate` → `CreateX` + `From<CreateX> for X`: key/version/internal
//!   fields omitted; the conversion fills key/version from each field's
//!   `#[serde(default = "path")]` fn (or `#[ldc(create_with = "path")]`).
//!   Echoed server fields (or any unknown field) are ignored: a stale `id`
//!   from an upsert-style client or a clipboard import never reaches the
//!   DB — the conversion re-assigns it.
//! - `LdUpdate` → `UpdateX` + `From<UpdateX> for X`: key/version kept but
//!   required (their serde/openapi optional-attrs stripped) so the client
//!   must echo the optimistic-lock `update_at`.
//! - `LdView` → `XView` + `From<X> for XView`: internal/hidden fields
//!   removed from responses.
//!
//! Shared field roles live in `#[ld(...)]`; per-derive customization in
//! `#[ldc(...)]` (create), `#[ldu(...)]` (update, reserved) and
//! `#[ldv(...)]` (view). Using a scoped attribute without deriving the
//! matching macro is a compile error, so typos never pass silently.
//!
//! | attribute | scope | meaning |
//! |---|---|---|
//! | `#[ld(internal)]` | all | server-only: excluded from every DTO; conversions fill `Default::default()` (the service re-derives it) |
//! | `#[ld(key)]` / `#[ld(version)]` | all | mark key/version explicitly when not named `id` / `update_at` |
//! | `#[ldc(create_with = "path")]` | `LdCreate` | conversion fill fn, overrides the serde default |
//! | `#[ldv(hidden)]` | `LdView` | omitted from responses only (writable, never read back) |
//! | `#[ldv(view_type(T))]` | `LdView` | view field uses type `T`, converted via `.into()` |
//!
//! Fields named `id`/`update_at` are recognized as key/version without
//! annotations. Business fields and their attrs are copied verbatim, so
//! optional business fields keep their current semantics. Example:
//!
//! ```ignore
//! #[derive(Debug, Clone, Serialize, Deserialize, LdCreate, LdUpdate, LdView)]
//! pub struct StaticNatMappingV4Config {
//!     #[serde(default = "gen_database_uuid")]
//!     pub id: Uuid,
//!     #[ld(internal)]
//!     pub wan_iface_name: Option<String>,
//!     #[serde(default = "get_f64_timestamp")]
//!     pub update_at: f64,
//!     ...
//! }
//! ```
//! generates `CreateStaticNatMappingV4Config` (no `id`/`update_at`/
//! `wan_iface_name`), `UpdateStaticNatMappingV4Config` (required `id` +
//! `update_at`) and `StaticNatMappingV4ConfigView` (no `wan_iface_name`).

use quote::{format_ident, quote};
use syn::{Attribute, Data, DeriveInput, Fields, Ident, Lit, LitStr, Type};

// ---------------------------------------------------------------------------
// Shared field model
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FieldKind {
    /// Plain business field: copied into every DTO verbatim.
    Normal,
    /// Server-assigned primary key: absent from `CreateX`, required in
    /// `UpdateX`, present in `XView`.
    Key,
    /// Optimistic-lock version: same treatment as [`FieldKind::Key`].
    Version,
    /// Server-internal field: excluded from every DTO; conversions fill
    /// `Default::default()` (the service re-derives it on write).
    Internal,
}

enum SerdeDefault {
    /// `#[serde(default = "path")]`
    Fn(LitStr),
    /// `#[serde(default)]`
    TraitDefault,
}

struct FieldInfo {
    ident: Ident,
    ty: Type,
    /// Original field attrs minus the `ld` family (serde / cfg_attr / doc kept).
    attrs: Vec<Attribute>,
    kind: FieldKind,
    serde_default: Option<SerdeDefault>,
    create_with: Option<LitStr>,
    hidden: bool,
    view_type: Option<Type>,
}

struct StructInfo {
    name: Ident,
    /// Container-level `#[serde(...)]` attrs (e.g. `rename_all`), copied onto
    /// every generated DTO.
    container_serde_attrs: Vec<Attribute>,
    fields: Vec<FieldInfo>,
}

fn is_ld_family(attr: &Attribute) -> bool {
    let p = attr.path();
    p.is_ident("ld") || p.is_ident("ldc") || p.is_ident("ldu") || p.is_ident("ldv")
}

fn parse_field(field: &syn::Field) -> FieldInfo {
    let ident = field
        .ident
        .clone()
        .unwrap_or_else(|| panic!("Ld* derives require named fields, found tuple/unit field"));

    let mut internal = false;
    let mut explicit_key = false;
    let mut explicit_version = false;
    let mut create_with: Option<LitStr> = None;
    let mut hidden = false;
    let mut view_type: Option<Type> = None;
    let mut serde_default: Option<SerdeDefault> = None;

    for attr in &field.attrs {
        let path = attr.path();
        if path.is_ident("ld") {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("internal") {
                    internal = true;
                } else if meta.path.is_ident("key") {
                    explicit_key = true;
                } else if meta.path.is_ident("version") {
                    explicit_version = true;
                } else {
                    return Err(meta.error(
                        "unknown #[ld(...)] item; expected `internal`, `key` or `version`",
                    ));
                }
                Ok(())
            })
            .unwrap_or_else(|e| panic!("Failed to parse #[ld(...)] on field `{}`: {}", ident, e));
        } else if path.is_ident("ldc") {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("create_with") {
                    let value = meta.value()?;
                    let lit: Lit = value.parse()?;
                    if let Lit::Str(s) = lit {
                        create_with = Some(s);
                    }
                    Ok(())
                } else {
                    Err(meta.error("unknown #[ldc(...)] item; expected `create_with = \"path\"`"))
                }
            })
            .unwrap_or_else(|e| panic!("Failed to parse #[ldc(...)] on field `{}`: {}", ident, e));
        } else if path.is_ident("ldu") {
            attr.parse_nested_meta(|meta| {
                Err(meta.error("#[ldu(...)] has no supported items yet; remove the attribute"))
            })
            .unwrap_or_else(|e| panic!("Failed to parse #[ldu(...)] on field `{}`: {}", ident, e));
        } else if path.is_ident("ldv") {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("hidden") {
                    hidden = true;
                    Ok(())
                } else if meta.path.is_ident("view_type") {
                    let content;
                    syn::parenthesized!(content in meta.input);
                    let ty: Type = content.parse()?;
                    view_type = Some(ty);
                    Ok(())
                } else {
                    Err(meta.error("unknown #[ldv(...)] item; expected `hidden` or `view_type(T)`"))
                }
            })
            .unwrap_or_else(|e| panic!("Failed to parse #[ldv(...)] on field `{}`: {}", ident, e));
        } else if path.is_ident("serde") {
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("default") {
                    if meta.input.peek(syn::Token![=]) {
                        let value = meta.value()?;
                        let lit: Lit = value.parse()?;
                        if let Lit::Str(s) = lit {
                            serde_default = Some(SerdeDefault::Fn(s));
                        }
                    } else {
                        serde_default = Some(SerdeDefault::TraitDefault);
                    }
                }
                Ok(())
            });
        }
    }

    let kind = if internal {
        FieldKind::Internal
    } else if explicit_key {
        FieldKind::Key
    } else if explicit_version {
        FieldKind::Version
    } else if ident == "id" {
        FieldKind::Key
    } else if ident == "update_at" {
        FieldKind::Version
    } else {
        FieldKind::Normal
    };

    if create_with.is_some() && !matches!(kind, FieldKind::Key | FieldKind::Version) {
        panic!(
            "Field `{}` is not a key/version field; #[ldc(create_with = ...)] only applies to server-assigned fields",
            ident
        );
    }

    let attrs: Vec<Attribute> = field.attrs.iter().filter(|a| !is_ld_family(a)).cloned().collect();

    FieldInfo {
        ident,
        ty: field.ty.clone(),
        attrs,
        kind,
        serde_default,
        create_with,
        hidden,
        view_type,
    }
}

fn parse_input(input: &DeriveInput) -> StructInfo {
    for attr in &input.attrs {
        if is_ld_family(attr) {
            panic!(
                "Container-level #[{}(...)] is not supported on `{}`; use field-level attributes",
                attr.path().get_ident().map(|i| i.to_string()).unwrap_or_default(),
                input.ident
            );
        }
    }
    let container_serde_attrs: Vec<Attribute> =
        input.attrs.iter().filter(|a| a.path().is_ident("serde")).cloned().collect();

    let fields: Vec<FieldInfo> = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(named) => named.named.iter().map(parse_field).collect(),
            _ => panic!("`{}`: Ld* derives only support structs with named fields", input.ident),
        },
        _ => panic!("`{}`: Ld* derives only support structs", input.ident),
    };

    let key_count = fields.iter().filter(|f| f.kind == FieldKind::Key).count();
    if key_count > 1 {
        panic!("`{}` has {} key fields; exactly one is allowed", input.ident, key_count);
    }

    StructInfo {
        name: input.ident.clone(),
        container_serde_attrs,
        fields,
    }
}

/// Derives + openapi gate shared by every generated DTO struct.
fn dto_header() -> proc_macro2::TokenStream {
    quote! {
        #[derive(Debug, Clone, ::serde::Serialize, ::serde::Deserialize)]
        #[cfg_attr(feature = "openapi", derive(::utoipa::ToSchema))]
    }
}

/// Fill expression for a key/version field in `From<CreateX>`.
/// Priority: `create_with` > `serde(default = "path")` > `serde(default)`;
/// without any, panic — a nil uuid quietly hitting the DB is a bug.
fn create_fill_expr(f: &FieldInfo, base: &Ident) -> proc_macro2::TokenStream {
    if let Some(with) = &f.create_with {
        let path: syn::Path = with
            .parse()
            .unwrap_or_else(|e| panic!("Invalid #[ldc(create_with)] path on `{}`: {}", f.ident, e));
        return quote! { #path() };
    }
    match &f.serde_default {
        Some(SerdeDefault::Fn(s)) => {
            let path: syn::Path = s.parse().unwrap_or_else(|e| {
                panic!("Invalid #[serde(default)] path on `{}`: {}", f.ident, e)
            });
            quote! { #path() }
        }
        Some(SerdeDefault::TraitDefault) => quote! { ::core::default::Default::default() },
        None => panic!(
            "Field `{}` on `{}` is server-assigned but has neither #[serde(default = \"...\")] nor #[ldc(create_with = \"...\")]; LdCreate cannot fill it",
            f.ident, base
        ),
    }
}

/// Field attrs for something that must become required: strip serde and
/// openapi optionality. NOTE: with the `openapi` feature on, rustc expands
/// `#[cfg_attr(feature = "openapi", schema(...))]` into a bare `#[schema(...)]`
/// *before* this derive runs — both forms must go.
fn bare_attrs(f: &FieldInfo) -> Vec<Attribute> {
    f.attrs
        .iter()
        .filter(|a| {
            let p = a.path();
            !(p.is_ident("serde") || p.is_ident("cfg_attr") || p.is_ident("schema"))
        })
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// LdCreate
// ---------------------------------------------------------------------------

/// Expansion behind `#[derive(LdCreate)]`.
pub(crate) fn expand_create(input: DeriveInput) -> proc_macro2::TokenStream {
    let info = parse_input(&input);
    let base = &info.name;
    let dto = format_ident!("Create{}", base);

    let kept: Vec<&FieldInfo> =
        info.fields.iter().filter(|f| f.kind == FieldKind::Normal).collect();

    let field_defs = kept.iter().map(|f| {
        let attrs = &f.attrs;
        let ident = &f.ident;
        let ty = &f.ty;
        quote! {
            #(#attrs)*
            pub #ident: #ty,
        }
    });

    let assigns = info.fields.iter().map(|f| {
        let ident = &f.ident;
        match f.kind {
            FieldKind::Normal => quote! { #ident: v.#ident },
            FieldKind::Key | FieldKind::Version => {
                let expr = create_fill_expr(f, base);
                quote! { #ident: #expr }
            }
            FieldKind::Internal => quote! { #ident: ::core::default::Default::default() },
        }
    });

    let server_fields: Vec<String> = info
        .fields
        .iter()
        .filter(|f| !matches!(f.kind, FieldKind::Normal))
        .map(|f| format!("`{}`", f.ident))
        .collect();
    let doc = format!(
        "Create-request DTO for [`{base}`]: server-assigned/internal fields ({}) are omitted; \
         convert with `From<{dto}> for {base}`.",
        server_fields.join(", ")
    );

    let container_serde_attrs = &info.container_serde_attrs;
    let header = dto_header();

    let expanded = quote! {
        #[doc = #doc]
        #header
        #(#container_serde_attrs)*
        pub struct #dto {
            #(#field_defs)*
        }

        impl ::core::convert::From<#dto> for #base {
            fn from(v: #dto) -> Self {
                Self {
                    #(#assigns,)*
                }
            }
        }
    };

    expanded
}

// ---------------------------------------------------------------------------
// LdUpdate
// ---------------------------------------------------------------------------

/// Expansion behind `#[derive(LdUpdate)]`.
pub(crate) fn expand_update(input: DeriveInput) -> proc_macro2::TokenStream {
    let info = parse_input(&input);
    let base = &info.name;
    let dto = format_ident!("Update{}", base);

    let kept: Vec<&FieldInfo> =
        info.fields.iter().filter(|f| f.kind != FieldKind::Internal).collect();

    let field_defs = kept.iter().map(|f| {
        let ident = &f.ident;
        let ty = &f.ty;
        let attrs = match f.kind {
            FieldKind::Key | FieldKind::Version => bare_attrs(f),
            _ => f.attrs.clone(),
        };
        quote! {
            #(#attrs)*
            pub #ident: #ty,
        }
    });

    let assigns = info.fields.iter().map(|f| {
        let ident = &f.ident;
        match f.kind {
            FieldKind::Internal => quote! { #ident: ::core::default::Default::default() },
            _ => quote! { #ident: v.#ident },
        }
    });

    let doc = format!(
        "Update-request DTO for [`{base}`]: `id`/`update_at` are required (optimistic lock); \
         internal fields are omitted and re-derived server-side."
    );

    let container_serde_attrs = &info.container_serde_attrs;
    let header = dto_header();

    let expanded = quote! {
        #[doc = #doc]
        #header
        #(#container_serde_attrs)*
        pub struct #dto {
            #(#field_defs)*
        }

        impl ::core::convert::From<#dto> for #base {
            fn from(v: #dto) -> Self {
                Self {
                    #(#assigns,)*
                }
            }
        }
    };

    expanded
}

// ---------------------------------------------------------------------------
// LdView
// ---------------------------------------------------------------------------

/// Expansion behind `#[derive(LdView)]`.
pub(crate) fn expand_view(input: DeriveInput) -> proc_macro2::TokenStream {
    let info = parse_input(&input);
    let base = &info.name;
    let dto = format_ident!("{}View", base);

    let is_hidden = |f: &FieldInfo| f.kind == FieldKind::Internal || f.hidden;

    if !info.fields.iter().any(|f| is_hidden(f) || f.view_type.is_some()) {
        panic!(
            "`{}` derives LdView but has no #[ld(internal)], #[ldv(hidden)] or #[ldv(view_type(...))] \
             field; `{}` would be identical to `{}` — remove the derive or mark fields",
            base, dto, base
        );
    }

    let kept: Vec<&FieldInfo> = info.fields.iter().filter(|f| !is_hidden(f)).collect();

    let field_defs = kept.iter().map(|f| {
        let attrs = &f.attrs;
        let ident = &f.ident;
        let ty = f.view_type.as_ref().unwrap_or(&f.ty);
        quote! {
            #(#attrs)*
            pub #ident: #ty,
        }
    });

    let assigns = kept.iter().map(|f| {
        let ident = &f.ident;
        if f.view_type.is_some() {
            quote! { #ident: v.#ident.into() }
        } else {
            quote! { #ident: v.#ident }
        }
    });

    let hidden_fields: Vec<String> =
        info.fields.iter().filter(|f| is_hidden(f)).map(|f| format!("`{}`", f.ident)).collect();
    let doc = format!(
        "Response-view DTO for [`{base}`]: server-only/hidden fields ({}) are never serialized to \
         the API.",
        hidden_fields.join(", ")
    );

    let container_serde_attrs = &info.container_serde_attrs;
    let header = dto_header();

    let expanded = quote! {
        #[doc = #doc]
        #header
        #(#container_serde_attrs)*
        pub struct #dto {
            #(#field_defs)*
        }

        impl ::core::convert::From<#base> for #dto {
            fn from(v: #base) -> Self {
                Self {
                    #(#assigns,)*
                }
            }
        }
    };

    expanded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn demo_input() -> DeriveInput {
        syn::parse_quote! {
            pub struct DemoConfig {
                #[serde(default = "gen_id")]
                #[cfg_attr(feature = "openapi", schema(required = false))]
                pub id: u64,
                pub name: String,
                #[serde(default = "now")]
                #[cfg_attr(feature = "openapi", schema(required = false))]
                pub update_at: f64,
            }
        }
    }

    #[test]
    fn update_dto_bares_key_and_version_fields() {
        let ts = expand_update(demo_input());
        let s = ts.to_string();
        let start = s.find("pub struct UpdateDemoConfig").unwrap();
        let struct_part = &s[start..];
        // serde/cfg_attr must be gone from the key/version fields
        assert!(
            !struct_part.contains("serde"),
            "key/version fields must be bare, got: {struct_part}"
        );
        assert!(!struct_part.contains("cfg_attr"), "got: {struct_part}");
    }

    /// With `openapi` on, rustc expands cfg_attr into a bare `#[schema(...)]`
    /// before this derive runs; that form must be stripped too.
    #[test]
    fn update_dto_bares_expanded_schema_attrs() {
        let input: DeriveInput = syn::parse_quote! {
            pub struct OpenApiExpandedConfig {
                #[serde(default = "gen_id")]
                #[schema(required = false)]
                pub id: u64,
                pub name: String,
                #[serde(default = "now")]
                #[schema(required = false)]
                pub update_at: f64,
            }
        };
        let ts = expand_update(input);
        let s = ts.to_string();
        let start = s.find("pub struct UpdateOpenApiExpandedConfig").unwrap();
        let struct_part = &s[start..];
        assert!(
            !struct_part.contains("schema"),
            "expanded #[schema(...)] must be stripped from key/version fields, got: {struct_part}"
        );
        assert!(!struct_part.contains("serde"), "got: {struct_part}");
    }
}
