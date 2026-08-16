pub mod pty;

/// All domain errors implement this trait to provide error_id and HTTP status code.
pub trait LdApiErrorInfo {
    fn error_id(&self) -> &'static str;
    fn http_status_code(&self) -> u16;
    fn error_args(&self) -> serde_json::Value {
        serde_json::json!({})
    }
}
