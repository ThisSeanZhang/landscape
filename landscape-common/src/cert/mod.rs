pub mod account;
pub mod order;

use landscape_macro::LdApiError;

use crate::config::ConfigId;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum CertError {
    #[error("Certificate account '{0}' not found")]
    #[api_error(id = "cert.account_not_found", status = 404)]
    AccountNotFound(ConfigId),

    #[error("Certificate order '{0}' not found")]
    #[api_error(id = "cert.order_not_found", status = 404)]
    OrderNotFound(ConfigId),
}
