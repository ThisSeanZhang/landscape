use landscape_macro::LdApiError;

use crate::config::ConfigId;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum FirewallError {
    #[error("Firewall rule '{0}' not found")]
    #[api_error(id = "firewall_rule.not_found", status = 404)]
    RuleNotFound(ConfigId),

    #[error("Firewall blacklist '{0}' not found")]
    #[api_error(id = "firewall_blacklist.not_found", status = 404)]
    BlacklistNotFound(ConfigId),
}
