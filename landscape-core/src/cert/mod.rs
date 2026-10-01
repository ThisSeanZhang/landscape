//! Shared TLS certificate support for the SNI resolvers used by the API and
//! gateway listeners.
//!
//! Module layout:
//! - [`resolver`]: [`SharedSniResolver`] — lock-free SNI resolution with
//!   exact / wildcard / fallback matching
//! - [`pem`]: PEM / X.509 parsing helpers (certified-key building, SAN
//!   extraction, validity parsing)
//! - [`reload`]: [`CertUsage`] + [`reload_tls_resolver`] orchestration that
//!   rebuilds the resolver snapshot from stored certs

mod pem;
mod reload;
mod resolver;

pub use pem::{
    build_certified_key_from_pem, extract_cert_dns_names_from_pem, parse_cert_validity_from_pem,
    validate_certified_key_from_pem,
};
pub use reload::{
    CertSnapshotProvider, CertUsage, build_tls_server_config_with_shared_resolver,
    reload_tls_resolver,
};
pub use resolver::SharedSniResolver;

#[cfg(test)]
mod tests;
