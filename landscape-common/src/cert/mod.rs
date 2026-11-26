pub mod account;
pub mod error;
pub mod order;
pub mod runtime;

pub use error::CertError;
pub use runtime::{CertIssuePhase, CertParsedInfo, CertTaskProgress};

#[cfg(test)]
mod tests {
    use super::{account::ProviderConfig, order::DnsProviderConfig};
    use serde_json::json;

    #[test]
    fn e2e_providers_are_opt_in() {
        let ca = json!({ "e2e": { "directory_url": "https://ca.lab.test/dir" } });
        let dns =
            json!({ "e2e": { "api_url": "http://dns.lab.test/client/v4", "api_token": "lab" } });
        let enabled = cfg!(feature = "e2e-acme");
        assert_eq!(serde_json::from_value::<ProviderConfig>(ca).is_ok(), enabled);
        assert_eq!(serde_json::from_value::<DnsProviderConfig>(dns).is_ok(), enabled);

        #[cfg(feature = "openapi")]
        {
            use utoipa::PartialSchema;
            for schema in [ProviderConfig::schema(), DnsProviderConfig::schema()] {
                let schema = serde_json::to_value(schema).unwrap();
                let variants = schema["oneOf"].as_array().unwrap();
                assert_eq!(variants.iter().any(|v| v["properties"].get("e2e").is_some()), enabled);
            }
        }
    }
}
