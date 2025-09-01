use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, Attribute, DeriveInput, Lit, Meta, MetaList, NestedMeta};

#[proc_macro_derive(LandscapeRequestModel, attributes(skip, ts))]
pub fn derive_request_model(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident.clone();
    let request_name = format_ident!("{}Request", name);
    let vis = input.vis.clone();

    let ts_attr_tokens = input
        .attrs
        .iter()
        .find(|attr| attr.path.is_ident("ts"))
        .cloned()
        .map(|attr| quote!(#attr)) // 这里是关键：quote 整个 Attribute
        .unwrap_or_default();

    let fields = match input.data {
        syn::Data::Struct(ref data) => &data.fields,
        _ => panic!("RequestModel only supports structs"),
    };

    let mut request_fields = vec![];
    let mut from_fields = vec![];

    for field in fields.iter() {
        let ident = field.ident.as_ref().unwrap();
        let ty = &field.ty;

        let skip_attr = field.attrs.iter().find(|a| a.path.is_ident("skip"));

        if let Some(attr) = skip_attr {
            // 解析 #[skip(default = "xxx")]
            let default_func = parse_skip_default(attr);
            let default_expr = if let Some(func) = default_func {
                quote! { #func() }
            } else {
                quote! { Default::default() }
            };
            from_fields.push(quote! { #ident: #default_expr });
        } else {
            // 正常字段
            request_fields.push(quote! {
                pub #ident: #ty
            });
            from_fields.push(quote! {
                #ident: req.#ident
            });
        }
    }

    let gen = quote! {
        #[derive(::serde::Serialize, ::serde::Deserialize, ::std::fmt::Debug, Clone, ::ts_rs::TS)]
        #ts_attr_tokens
        #vis struct #request_name {
            #( #request_fields, )*
        }

        impl From<#request_name> for #name {
            fn from(req: #request_name) -> Self {
                Self {
                    #( #from_fields, )*
                }
            }
        }
    };

    gen.into()
}

fn parse_skip_default(attr: &Attribute) -> Option<syn::Path> {
    if let Ok(Meta::List(MetaList { nested, .. })) = attr.parse_meta() {
        for item in nested {
            if let NestedMeta::Meta(Meta::NameValue(nv)) = item {
                if nv.path.is_ident("default") {
                    if let Lit::Str(lit) = nv.lit {
                        return Some(lit.parse().unwrap());
                    }
                }
            }
        }
    }
    None
}
