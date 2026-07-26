use landscape_macro::LdApiError;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum LanHostnameError {
    #[error("Invalid IDNA LAN hostname suffix '{suffix}'")]
    #[api_error(id = "lan_hostname.invalid_suffix.invalid_idna", status = 400)]
    InvalidIdna { suffix: String },

    #[error("LAN hostname suffix '{suffix}' contains an empty DNS label")]
    #[api_error(id = "lan_hostname.invalid_suffix.empty_label", status = 400)]
    EmptyLabel { suffix: String },

    #[error("LAN hostname suffix '{suffix}' exceeds DNS name or label length limits")]
    #[api_error(id = "lan_hostname.invalid_suffix.too_long", status = 400)]
    TooLong { suffix: String },

    #[error("LAN hostname suffix '{suffix}' cannot start or end with a hyphen")]
    #[api_error(id = "lan_hostname.invalid_suffix.invalid_hyphen", status = 400)]
    InvalidHyphen { suffix: String },

    #[error("LAN hostname suffix '{suffix}' may contain only letters, digits, and hyphens")]
    #[api_error(id = "lan_hostname.invalid_suffix.invalid_character", status = 400)]
    InvalidCharacter { suffix: String },

    #[error("LAN hostname suffix '{suffix}' is reserved by the DNS resolver")]
    #[api_error(id = "lan_hostname.invalid_suffix.reserved", status = 400)]
    Reserved { suffix: String },
}
