use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Meta};

pub fn export_ts_enum(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let enum_ident = &input.ident;
    let enum_name = format!("{}TsEnum", enum_ident);
    let enum_ident_ts = syn::Ident::new(&enum_name, enum_ident.span());

    let copied_attrs = input.attrs.iter().filter(|attr| {
        if attr.path.is_ident("ts") {
            return true;
        }

        if attr.path.is_ident("serde") {
            // 检查 serde 的内容
            if let Ok(Meta::List(meta_list)) = attr.parse_meta() {
                // 如果包含 tag=...，则跳过
                let has_tag = meta_list.nested.iter().any(|nested| {
                    if let syn::NestedMeta::Meta(Meta::NameValue(nv)) = nested {
                        nv.path.is_ident("tag")
                    } else {
                        false
                    }
                });
                return !has_tag;
            }
        }

        false
    });

    let data = match &input.data {
        syn::Data::Enum(e) => e,
        _ => panic!("ExportTsEnum only supports enum"),
    };

    let variants = data.variants.iter().map(|v| {
        let ident = &v.ident;
        quote! {
            #ident
        }
    });

    let expanded = quote! {
        #[derive(::serde::Serialize, ::serde::Deserialize, ::ts_rs::TS)]
        #(#copied_attrs)*
        pub enum #enum_ident_ts {
            #(#variants),*
        }
    };

    expanded.into()
}
